<?php

namespace SSO;

abstract class OAuthProxy
{
    protected array $clients;
    protected array $providerConfig;
    protected RedisState $stateStore;
    protected Logger $logger;
    protected string $baseUrl;

    public function __construct(RedisState $stateStore, Logger $logger)
    {
        $this->clients = require __DIR__ . '/../config/clients.php';
        $providers = require __DIR__ . '/../config/providers.php';
        $this->providerConfig = $providers[$this->getProviderName()];
        $this->stateStore = $stateStore;
        $this->logger = $logger;
        $this->baseUrl = rtrim(getenv('APP_BASE_URL') ?: 'http://localhost:8080', '/');
    }

    abstract protected function getProviderName(): string;

    abstract protected function buildAuthUrl(string $state): string;

    abstract protected function getCallbackPath(): string;

    /**
     * Exchange authorization code with the provider's token endpoint.
     */
    abstract protected function exchangeCodeWithProvider(string $code): ?array;

    /**
     * Fetch user info from the provider using access token.
     * Returns normalized array in Google-compatible format.
     */
    abstract protected function fetchUserInfoFromProvider(string $accessToken): ?array;

    public function auth(): void
    {
        $clientId    = $_GET['client_id'] ?? '';
        $redirectUri = $_GET['redirect_uri'] ?? '';

        if (!isset($this->clients[$clientId])) {
            $this->logger->warning('Invalid client_id', ['client_id' => $clientId]);
            JsonResponse::error(400, 'invalid_client', 'Unknown client_id');
        }

        $allowedUris = $this->clients[$clientId]['redirect_uris'] ?? [];
        if (!in_array($redirectUri, $allowedUris, true)) {
            $this->logger->warning('Redirect URI not in whitelist', [
                'client_id'    => $clientId,
                'redirect_uri' => $redirectUri,
            ]);
            JsonResponse::error(400, 'invalid_redirect_uri', 'redirect_uri is not registered for this client');
        }

        $state = bin2hex(random_bytes(16));
        $this->stateStore->set($state, [
            'client_id'    => $clientId,
            'redirect_uri' => $redirectUri,
            'provider'     => $this->getProviderName(),
        ]);

        $authUrl = $this->buildAuthUrl($state);

        $this->logger->info('Redirecting to OAuth provider', [
            'provider'  => $this->getProviderName(),
            'client_id' => $clientId,
        ]);

        header('Location: ' . $authUrl);
        exit;
    }

    /**
     * Callback from provider: wrap the code with provider info and redirect to client.
     * The wrapped_code is stored in Redis so /token knows which provider to call.
     */
    public function callback(): void
    {
        $state = $_GET['state'] ?? '';
        $code  = $_GET['code'] ?? '';
        $error = $_GET['error'] ?? '';

        if ($error) {
            $errorDesc = $_GET['error_description'] ?? 'Unknown error from OAuth provider';
            $this->logger->error('OAuth provider returned error', [
                'provider' => $this->getProviderName(),
                'error'    => $error,
                'desc'     => $errorDesc,
            ]);
            JsonResponse::error(502, 'provider_error', $errorDesc);
        }

        if (empty($state) || empty($code)) {
            $this->logger->warning('Missing state or code in callback');
            JsonResponse::error(400, 'invalid_request', 'Missing state or code parameter');
        }

        $data = $this->stateStore->get($state);
        if (!$data) {
            $this->logger->warning('Invalid or expired state', ['state' => substr($state, 0, 8) . '...']);
            JsonResponse::error(400, 'invalid_state', 'State token is invalid or expired');
        }

        $this->stateStore->delete($state);

        if (($data['provider'] ?? '') !== $this->getProviderName()) {
            $this->logger->error('State provider mismatch', [
                'expected' => $this->getProviderName(),
                'actual'   => $data['provider'] ?? 'unknown',
            ]);
            JsonResponse::error(400, 'invalid_state', 'State token does not match this provider');
        }

        $redirectUri = $data['redirect_uri'];

        // Store original code + provider in Redis with a wrapped code
        // So when client calls /token, we know which provider to exchange with
        $wrappedCode = bin2hex(random_bytes(32));
        $this->stateStore->setCodeMapping($wrappedCode, [
            'provider'      => $this->getProviderName(),
            'original_code' => $code,
            'client_id'     => $data['client_id'],
        ]);

        $this->logger->info('Wrapping auth code and redirecting to client', [
            'provider'  => $this->getProviderName(),
            'client_id' => $data['client_id'],
        ]);

        // Redirect to client with wrapped code (same as before, client sees ?code=xxx)
        $separator = str_contains($redirectUri, '?') ? '&' : '?';
        header('Location: ' . $redirectUri . $separator . 'code=' . urlencode($wrappedCode));
        exit;
    }

    /**
     * /token endpoint: Client exchanges wrapped code → SSO Hub exchanges with provider → returns token.
     * Response format is Google-compatible.
     */
    public static function tokenEndpoint(RedisState $stateStore, Logger $logger): void
    {
        // Accept both POST (standard) and GET
        $code = $_POST['code'] ?? $_GET['code'] ?? '';

        if (empty($code)) {
            JsonResponse::error(400, 'invalid_request', 'Missing code parameter');
        }

        // Look up the wrapped code
        $mapping = $stateStore->getCodeMapping($code);
        if (!$mapping) {
            $logger->warning('Invalid or expired wrapped code', ['code' => substr($code, 0, 8) . '...']);
            JsonResponse::error(400, 'invalid_grant', 'Code is invalid or expired');
        }

        // Delete immediately (one-time use)
        $stateStore->deleteCodeMapping($code);

        $providerName = $mapping['provider'];
        $originalCode = $mapping['original_code'];

        // Create the correct proxy based on provider
        $providers = require __DIR__ . '/../config/providers.php';
        $proxy = match ($providerName) {
            'google'    => new \SSO\GoogleProxy($stateStore, $logger),
            'microsoft' => new \SSO\MicrosoftProxy($stateStore, $logger),
            default     => null,
        };

        if (!$proxy) {
            JsonResponse::error(400, 'invalid_provider', 'Unknown provider: ' . $providerName);
        }

        // Exchange original code with the real provider
        $tokenResponse = $proxy->exchangeCodeWithProvider($originalCode);

        if (!$tokenResponse || isset($tokenResponse['error'])) {
            $logger->error('Token exchange with provider failed', [
                'provider' => $providerName,
                'error'    => $tokenResponse['error'] ?? 'unknown',
            ]);
            JsonResponse::error(502, 'token_exchange_failed',
                $tokenResponse['error_description'] ?? 'Failed to exchange code with provider');
        }

        // Store access_token → provider mapping so /userinfo knows which provider to call
        $accessToken = $tokenResponse['access_token'] ?? '';
        if ($accessToken) {
            $ttl = $tokenResponse['expires_in'] ?? 3600;
            $stateStore->setTokenProvider($accessToken, [
                'provider' => $providerName,
            ], (int) $ttl);
        }

        $logger->info('Token exchanged successfully', [
            'provider' => $providerName,
        ]);

        // Return token response in Google-compatible format
        JsonResponse::success([
            'access_token'  => $tokenResponse['access_token'] ?? '',
            'token_type'    => $tokenResponse['token_type'] ?? 'Bearer',
            'expires_in'    => $tokenResponse['expires_in'] ?? 3600,
            'refresh_token' => $tokenResponse['refresh_token'] ?? null,
            'id_token'      => $tokenResponse['id_token'] ?? null,
            'scope'         => $tokenResponse['scope'] ?? '',
            'provider'      => $providerName,
        ]);
    }

    /**
     * /userinfo endpoint: Client sends access_token → SSO Hub fetches from provider → returns user info.
     * Response format is Google-compatible (same fields as Google OAuth2 userinfo).
     */
    public static function userinfoEndpoint(RedisState $stateStore, Logger $logger): void
    {
        // Get access token from Authorization header, Apache env, or query param
        $accessToken = '';
        $authHeader = '';
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
        } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $authHeader = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        } elseif (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            if (isset($headers['Authorization'])) {
                $authHeader = $headers['Authorization'];
            } elseif (isset($headers['authorization'])) {
                $authHeader = $headers['authorization'];
            }
        }
        if (preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
            $accessToken = $matches[1];
        }
        if (empty($accessToken)) {
            $accessToken = isset($_GET['access_token']) ? $_GET['access_token'] : '';
        }

        if (empty($accessToken)) {
            JsonResponse::error(401, 'invalid_request', 'Missing access_token (use Authorization: Bearer header or access_token param)');
        }

        // Look up which provider this token belongs to
        $tokenData = $stateStore->getTokenProvider($accessToken);
        if (!$tokenData) {
            $logger->warning('Unknown access_token for userinfo');
            JsonResponse::error(401, 'invalid_token', 'Access token is not recognized. Call /token first.');
        }

        $providerName = $tokenData['provider'];

        $proxy = match ($providerName) {
            'google'    => new \SSO\GoogleProxy($stateStore, $logger),
            'microsoft' => new \SSO\MicrosoftProxy($stateStore, $logger),
            default     => null,
        };

        if (!$proxy) {
            JsonResponse::error(400, 'invalid_provider', 'Unknown provider');
        }

        $userInfo = $proxy->fetchUserInfoFromProvider($accessToken);

        if (!$userInfo || isset($userInfo['error'])) {
            $logger->error('Failed to fetch userinfo from provider', [
                'provider' => $providerName,
            ]);
            JsonResponse::error(502, 'userinfo_failed', 'Failed to fetch user info from provider');
        }

        $logger->info('User info fetched successfully', [
            'provider' => $providerName,
            'email'    => $userInfo['email'] ?? 'unknown',
        ]);

        // Return in Google OAuth2 userinfo format
        JsonResponse::success($userInfo);
    }

    /**
     * Helper: HTTP POST request.
     */
    protected function httpPost(string $url, array $params, array $headers = []): ?array
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        if ($headers) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            $this->logger->error('HTTP POST failed', ['url' => $url, 'error' => $error]);
            return null;
        }

        return json_decode($response, true) ?: null;
    }

    /**
     * Helper: HTTP GET with Bearer token.
     */
    protected function httpGetWithToken(string $url, string $token): ?array
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $token]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            $this->logger->error('HTTP GET failed', ['url' => $url, 'error' => $error]);
            return null;
        }

        return json_decode($response, true) ?: null;
    }
}
