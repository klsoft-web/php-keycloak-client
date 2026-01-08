<?php

namespace Klsoft\KeycloakClient;

use InvalidArgumentException;

/**
 * Securing web applications with Keycloak. It is typically used in conjunction with RESTful web service APIs.
 */
class KeycloakClient
{
    private string $realmAuthorizationUrl;
    private string $realmTokenUrl;
    private string $realmLogoutUrl;
    private string $realmUserInfoUrl;

    /**
     * @param string $realmUrl Keycloak realm URL
     * @param string $clientId Keycloak client ID
     * @param string $redirectUri Keycloak client redirect URI
     * @param ?string $clientSecret Keycloak client secret. This is optional, but it is required when Keycloak 'Client authentication' is ON
     */
    public function __construct(
        private readonly string  $realmUrl,
        private readonly string  $clientId,
        private readonly string  $redirectUri,
        private readonly ?string $clientSecret = null)
    {
        if (empty($realmUrl)) {
            throw new InvalidArgumentException('The argument \'realmUrl\' must not be empty');
        }

        if (empty($clientId)) {
            throw new InvalidArgumentException('The argument \'clientId\' must not be empty');
        }

        if (empty($redirectUri)) {
            throw new InvalidArgumentException('The argument \'redirectUri\' must not be empty');
        }

        $this->realmAuthorizationUrl = "$this->realmUrl/protocol/openid-connect/auth";
        $this->realmTokenUrl = "$this->realmUrl/protocol/openid-connect/token";
        $this->realmLogoutUrl = "$this->realmUrl/protocol/openid-connect/logout";
        $this->realmUserInfoUrl = "$this->realmUrl/protocol/openid-connect/userinfo";
    }

    /**
     * Create an Authorization Code flow URL for the Keycloak login form.
     *
     * @param string $scope
     *
     * @return string A URL for the Keycloak login form
     *
     * @throws InvalidArgumentException
     */
    public function createAuthorizationCodeLoginUrl(string $scope = 'openid'): string
    {
        if (empty($scope)) {
            throw new InvalidArgumentException('The argument \'scope\' must not be empty');
        }

        return "$this->realmAuthorizationUrl?client_id=$this->clientId&response_type=code&scope=" . urlencode($scope) . "&redirect_uri=" . urlencode($this->redirectUri) . "&state={$this->generateGUID()}&nonce={$this->generateGUID()}";
    }

    private function generateGUID(): string
    {
        return sprintf(
            '%04X%04X-%04X-%04X-%04X-%04X%04X%04X',
            mt_rand(0, 65535),
            mt_rand(0, 65535),
            mt_rand(0, 65535),
            mt_rand(16384, 20479),
            mt_rand(32768, 49151),
            mt_rand(0, 65535),
            mt_rand(0, 65535),
            mt_rand(0, 65535));
    }

    /**
     * Create an Implicit flow URL for the Keycloak login form.
     *
     * @param string $scope
     *
     * @return string A URL for the Keycloak login form
     *
     * @throws InvalidArgumentException
     */
    public function createImplicitLoginUrl(string $scope = 'openid'): string
    {
        if (empty($scope)) {
            throw new InvalidArgumentException('The argument \'scope\' must not be empty');
        }

        return "$this->realmAuthorizationUrl?client_id=$this->clientId&response_type=" . urlencode("id_token token") . "&scope=" . urlencode($scope) . "&redirect_uri=" . urlencode($this->redirectUri) . "&state={$this->generateGUID()}&nonce={$this->generateGUID()}";
    }

    /**
     * Obtain a token using an Authorization Code.
     *
     * @param string $code An Authorization Code
     * @return ResponseResult
     *
     * @throws InvalidArgumentException
     */
    public function getTokenByAuthorizationCode(string $code): ResponseResult
    {
        if (empty($code)) {
            throw new InvalidArgumentException('The argument \'code\' must not be empty');
        }

        $data = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId
        ];
        if (!empty($this->clientSecret)) {
            $data['client_secret'] = $this->clientSecret;
        }
        $options = [
            'http' => [
                'ignore_errors' => true,
                'method' => 'POST',
                'header' => 'Content-type: application/x-www-form-urlencoded',
                'content' => http_build_query($data)
            ],
        ];
        return $this->executeRequest($this->realmTokenUrl, $options);
    }

    private function executeRequest(
        string $url,
        array  $options): ResponseResult
    {
        $responseData = file_get_contents($url, false, stream_context_create($options));
        $responseStatusCode = $this->getHttpResponseStatusCode($http_response_header[0]);
        if (!empty($responseData)) {
            return new ResponseResult($responseStatusCode, json_decode($responseData, false));
        }
        return new ResponseResult($responseStatusCode, (object)[]);

    }

    private function getHttpResponseStatusCode(string $responseHeader): int
    {
        if (preg_match("/^HTTP\/[\d.]+\s+(\d{3})\s.*$/", $responseHeader, $matches)) {
            return intval($matches[1]);
        }
        return 0;
    }

    /**
     * Obtain a token using client credentials. This method can only be used by confidential clients. Make sure that both the 'Client authentication' and 'Service accounts roles' options are ON in Keycloak.
     *
     * @return ResponseResult
     *
     * @throws InvalidArgumentException
     */
    public function getTokenByClientCredentials(): ResponseResult
    {
        if (empty($this->clientSecret)) {
            throw new InvalidArgumentException('The constructor argument \'clientSecret\' must not be empty');
        }

        $data = [
            'grant_type' => 'client_credentials',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret
        ];
        $options = [
            'http' => [
                'ignore_errors' => true,
                'method' => 'POST',
                'header' => 'Content-type: application/x-www-form-urlencoded',
                'content' => http_build_query($data)
            ],
        ];
        return $this->executeRequest($this->realmTokenUrl, $options);
    }

    /**
     * Refresh a token.
     *
     * @param string $refreshToken
     *
     * @return ResponseResult
     *
     * @throws InvalidArgumentException
     */
    public function refreshToken(string $refreshToken): ResponseResult
    {
        if (empty($refreshToken)) {
            throw new InvalidArgumentException('The argument refreshToken must not be empty');
        }

        $data = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->clientId,
        ];
        if (!empty($this->clientSecret)) {
            $data['client_secret'] = $this->clientSecret;
        }
        $options = [
            'http' => [
                'ignore_errors' => true,
                'method' => 'POST',
                'header' => 'Content-type: application/x-www-form-urlencoded',
                'content' => http_build_query($data)
            ],
        ];
        return $this->executeRequest($this->realmTokenUrl, $options);
    }

    /**
     * Get a Requesting Party Token by a permission ticket.
     *
     * @param string $accessToken
     * @param string $permissionTicket
     *
     * @return ResponseResult
     *
     * @throws InvalidArgumentException
     */
    public function getRequestingPartyTokenByPermissionTicket(
        string $accessToken,
        string $permissionTicket): ResponseResult
    {
        if (empty($accessToken)) {
            throw new InvalidArgumentException('The argument \'accessToken\' must not be empty');
        }

        if (empty($permissionTicket)) {
            throw new InvalidArgumentException('The argument \'permissionTicket\' must not be empty');
        }

        $data = [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:uma-ticket',
            'ticket' => $permissionTicket
        ];
        $options = [
            'http' => [
                'ignore_errors' => true,
                'method' => 'POST',
                'header' => [
                    "Content-type: application/x-www-form-urlencoded",
                    "Authorization: Bearer $accessToken"],
                'content' => http_build_query($data)
            ],
        ];
        return $this->executeRequest($this->realmTokenUrl, $options);
    }

    /**
     * Get a Requesting Party Token by the client ID.
     *
     * @param string $accessToken
     *
     * @return ResponseResult
     *
     * @throws InvalidArgumentException
     */
    public function getRequestingPartyTokenByClientId(string $accessToken): ResponseResult
    {
        if (empty($accessToken)) {
            throw new InvalidArgumentException('The argument \'accessToken\' must not be empty');
        }

        $data = [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:uma-ticket',
            'audience' => $this->clientId
        ];
        $options = [
            'http' => [
                'ignore_errors' => true,
                'method' => 'POST',
                'header' => [
                    "Content-type: application/x-www-form-urlencoded",
                    "Authorization: Bearer $accessToken"],
                'content' => http_build_query($data)
            ],
        ];
        return $this->executeRequest($this->realmTokenUrl, $options);
    }

    /**
     * Logout.
     *
     * @param string $refreshToken
     *
     * @return ResponseResult
     *
     * @throws InvalidArgumentException
     */
    public function logout(string $refreshToken): ResponseResult
    {
        if (empty($refreshToken)) {
            throw new InvalidArgumentException('The argument \'refreshToken\' must not be empty');
        }

        $data = [
            'refresh_token' => $refreshToken,
            'client_id' => $this->clientId
        ];
        if (!empty($this->clientSecret)) {
            $data['client_secret'] = $this->clientSecret;
        }
        $options = [
            'http' => [
                'ignore_errors' => true,
                'method' => 'POST',
                'header' => 'Content-type: application/x-www-form-urlencoded',
                'content' => http_build_query($data)
            ],
        ];
        return $this->executeRequest($this->realmLogoutUrl, $options);
    }

    /**
     * Get a userinfo by a bearer token.
     *
     * @param string $accessToken
     *
     * @return ResponseResult
     *
     * @throws InvalidArgumentException
     */
    public function getUserInfo(string $accessToken): ResponseResult
    {
        if (empty($accessToken)) {
            throw new InvalidArgumentException('The argument \'accessToken\' must not be empty');
        }

        $options = [
            'http' => [
                'ignore_errors' => true,
                'method' => 'GET',
                'header' => "Authorization: Bearer $accessToken"
            ],
        ];
        return $this->executeRequest($this->realmUserInfoUrl, $options);
    }

    /**
     * @param string $realmAuthorizationUrl Realm authorization URL.
     *
     * @return self
     */
    public function withRealmAuthorizationUrl(string $realmAuthorizationUrl): self
    {
        $new = clone $this;
        $new->realmAuthorizationUrl = $realmAuthorizationUrl;
        return $new;
    }

    /**
     * @param string $realmTokenUrl Realm token URL.
     *
     * @return self
     */
    public function withRealmTokenUrl(string $realmTokenUrl): self
    {
        $new = clone $this;
        $new->realmTokenUrl = $realmTokenUrl;
        return $new;
    }

    /**
     * @param string $realmLogoutUrl Realm logout URL.
     *
     * @return self
     */
    public function withRealmLogoutUrl(string $realmLogoutUrl): self
    {
        $new = clone $this;
        $new->realmLogoutUrl = $realmLogoutUrl;
        return $new;
    }

    /**
     * @param string $realmUserInfoUrl Realm userinfo URL.
     *
     * @return self
     */
    public function withRealmUserInfoUrl(string $realmUserInfoUrl): self
    {
        $new = clone $this;
        $new->realmUserInfoUrl = $realmUserInfoUrl;
        return $new;
    }
}
