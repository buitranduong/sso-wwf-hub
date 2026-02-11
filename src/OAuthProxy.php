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

        $this->logger->info('Proxying auth code to client', [
            'provider'  => $this->getProviderName(),
            'client_id' => $data['client_id'],
        ]);

        $separator = str_contains($redirectUri, '?') ? '&' : '?';
        header('Location: ' . $redirectUri . $separator . 'code=' . urlencode($code));
        exit;
    }
}
