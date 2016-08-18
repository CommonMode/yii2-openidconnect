<?php
namespace commonmode\authclient;

use Yii;
use yii\web\HttpException;
use yii\authclient\OAuth2;
use yii\authclient\OAuthToken;
use Jose\Factory\JWKFactory;
use Jose\Loader;

/**
 * OpenIdConnect serves as a client for the OpenID Connect flow.
 *
 * In oder to acquire access token perform following sequence:
 *
 * ```php
 * use commonmode\authclient\OpenIdConnect;
 *
 * $openIdConnectClient = new OpenIdConnect();
 * $url = $openIdConnectClient->buildAuthUrl(); // Build authorization URL
 * Yii::$app->getResponse()->redirect($url); // Redirect to authorization URL.
 * // After user returns at our site:
 * $code = $_GET['code'];
 * $accessToken = $openIdConnectClient->fetchAccessToken($code); // Get access token
 * ```
 *
 * @see http://openid.net/specs/openid-connect-core-1_0.html
 *
 * @author George Gardiner <george.gardiner@commonmode.co.uk>
 */
class OpenIdConnect extends OAuth2
{
    /**
     * @var string protocol version.
     */
    public $version = "Connect";

    /**
     * @var string url of OP
     */
    public $providerUrl;

    /**
     * @var bool create and validate a nonce as part of the flow
     */
    public $validateNonce = true;

    /**
     * @var array protocol version.
     */
    private $providerConfig = [];

    /**
     * @var array authParams to forward to OP
     */
    private $authParams = [];

    /**
     * @var array response types to request from OP
     */
    private $responseTypes = ['code'];

    /**
     * @var array scopes to request from OP
     */
    private $scopes = ['openid'];

    /**
     * @var array alg values that are authorised for use.
     */
    public $allowedAlgorithms = [
        'HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512',
        'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'
    ];

    /**
     * Composes user authorization URL.
     * @param array $params additional auth GET params.
     * @return string authorization URL.
     */
    public function buildAuthUrl(array $params = [])
    {
        $this->authUrl = $this->discover("authorization_endpoint");

        $defaultParams = [
            'response_type' => implode(' ', $this->responseTypes),
            'redirect_uri' => $this->getReturnUrl(),
            'client_id' => $this->clientId,
            'scope' => implode(' ', $this->scopes)
        ];

        if ($this->validateAuthState) {
            $authState = $this->generateAuthState();
            $this->setState('authState', $authState);
            $defaultParams['state'] = $authState;
        }

        if ($this->validateNonce) {
            $nonce = $this->generateNonce();
            $this->setState('authNonce', $nonce);
            $defaultParams['nonce'] = $nonce;
        }

        return $this->composeUrl($this->authUrl, array_merge($defaultParams, $params));
    }

    /**
     * Fetches access token from authorization code.
     * @param string $authCode authorization code, usually comes at $_GET['code'].
     * @param array $params additional request params.
     * @return OAuthToken access token.
     * @throws HttpException on invalid auth state in case [[enableStateValidation]] is enabled.
     */
    public function fetchAccessToken($authCode, array $params = [])
    {
        if ($this->validateAuthState) {
            $authState = $this->getState('authState');
            if (!isset($_REQUEST['state']) || empty($authState) || strcmp($_REQUEST['state'], $authState) !== 0) {
                throw new HttpException(400, 'Invalid auth state parameter.');
            } else {
                $this->removeState('authState');
            }
        }

        $headers = [];

        $defaultParams = [
            'grant_type' => 'authorization_code',
            'code' => $authCode,
            'redirect_uri' => $this->getReturnUrl(),
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        if (in_array('client_secret_basic', $this->discover("token_endpoint_auth_methods_supported"))) {
            $headers = ['Authorization: Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret)];
            unset($defaultParams['client_secret']);
        }

        $request = $this->createRequest()
            ->setMethod('POST')
            ->setUrl($this->discover("token_endpoint"))
            ->setData(array_merge($defaultParams, $params))
            ->setHeaders($headers);

        $response = $this->sendRequest($request);

        $jwkSet = JWKFactory::createFromJKU($this->discover('jwks_uri'));
        $loader = new Loader();
        $idToken = $loader->loadAndVerifySignatureUsingKeySet(
            $response['id_token'],
            $jwkSet,
            $this->allowedAlgorithms
        )->getPayload();
        $accessToken = $loader->loadAndVerifySignatureUsingKeySet(
            $response['access_token'],
            $jwkSet,
            $this->allowedAlgorithms
        )->getPayload();

        $this->validateClaims($idToken);
        $this->validateClaims($accessToken);

        if ($this->validateNonce) {
            $nonce = $this->getState('authNonce');
            if (!isset($idToken['nonce']) || empty($nonce) || strcmp($idToken['nonce'], $nonce) !== 0) {
                throw new HttpException(400, 'Invalid nonce.');
            } else {
                $this->removeState('authNonce');
            }
        }

        $token = $this->createToken(['params' => array_merge($response, $idToken, $accessToken)]);
        $this->setAccessToken($token);
        return $token;
    }

    /**
     * Gets new auth token to replace expired one.
     * @param OAuthToken $token expired auth token.
     * @return OAuthToken new auth token.
     */
    public function refreshAccessToken(OAuthToken $token)
    {
        $params = [
            'grant_type' => 'refresh_token',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret
        ];

        $headers = [];

        if (in_array('client_secret_basic', $this->discover("token_endpoint_auth_methods_supported"))) {
            $headers = ['Authorization: Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret)];
            unset($params['client_secret']);
        }

        $params = array_merge($token->getParams(), $params);

        $request = $this->createRequest()
            ->setMethod('POST')
            ->setUrl($this->discover("token_endpoint"))
            ->setData($params)
            ->setHeaders($headers);

        $response = $this->sendRequest($request);

        $jwkSet = JWKFactory::createFromJKU($this->discover('jwks_uri'));
        $loader = new Loader();
        $idToken = $loader->loadAndVerifySignatureUsingKeySet(
            $response['id_token'],
            $jwkSet,
            $this->allowedAlgorithms
        )->getPayload();
        $accessToken = $loader->loadAndVerifySignatureUsingKeySet(
            $response['access_token'],
            $jwkSet,
            $this->allowedAlgorithms
        )->getPayload();

        $this->validateClaims($idToken);
        $this->validateClaims($accessToken);
        $token = $this->createToken(['params' => array_merge($response, $idToken, $accessToken)]);
        $this->setAccessToken($token);
        return $token;
    }


    /**
     * Check the validity of claims made by the OP
     * @param array $claims an array of claims made
     * @throws HttpException
     */
    private function validateClaims(array $claims)
    {
        if (!isset($claims['iss']) || (strcmp($claims['iss'], $this->getProviderURL()) !== 0)) {
            throw new HttpException(400, 'Invalid iss');
        }
        if (!isset($claims['aud']) || (strcmp($claims['aud'], $this->clientId) !== 0)) {
            throw new HttpException(400, 'Invalid aud');
        }
    }

    /**
     * Generate a secure random nonce
     */
    private function generateNonce()
    {
        $nonce = Yii::$app->security->generateRandomString();
        return $nonce;
    }

    /**
     * Auto discover parameters from the OP
     * @param string $param the attribute to discover
     * @throws HttpException
     */
    private function discover($param)
    {
        if (!isset($this->providerConfig[$param])) {
            $request = $this->createRequest()
                ->setMethod('GET')
                ->setUrl(rtrim($this->getProviderURL(), "/") . "/.well-known/openid-configuration");

            $response = $this->sendRequest($request);
            if (isset($response[$param])) {
                $this->providerConfig[$param] = $response[$param];
            } else {
                throw new HttpException("Could not discover " . $param . " from .well-known/openid-configuration");
            }
        }
        return $this->providerConfig[$param];
    }

    /**
     * Get the base URL of the OP
     * @return string the url of the OP
     * @throws HttpException
     */
    public function getProviderURL()
    {
        if (!isset($this->providerUrl)) {
            throw new HttpException("The provider URL has not been set");
        } else {
            return $this->providerUrl;
        }
    }

    /**
     * Add a scope to be requested in the auth flow eg. openid, profile, email
     */
    public function addScope($scope)
    {
        $this->scopes = array_merge($this->scopes, (array)$scope);
    }

    /**
     * Add a parameter to be passed in the auth flow eg. prompt=login
     */
    public function addAuthParam($param)
    {
        $this->authParams = array_merge($this->authParams, (array)$param);
    }

    /**
     * @inheritdoc
     */
    public function initUserAttributes()
    {
        $endpoint = $this->discover("userinfo_endpoint");
        return $this->api($endpoint, 'GET');
    }

}