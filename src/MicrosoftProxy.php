<?php

namespace SSO;

class MicrosoftProxy extends OAuthProxy
{
    protected function getProviderName(): string
    {
        return 'microsoft';
    }

    protected function getCallbackPath(): string
    {
        return '/microsoft/callback';
    }

    protected function buildAuthUrl(string $state): string
    {
        $tenantId = $this->providerConfig['tenant_id'] ?? 'common';
        $authUrl  = sprintf($this->providerConfig['auth_url'], $tenantId);

        $params = http_build_query([
            'client_id'     => $this->providerConfig['client_id'],
            'redirect_uri'  => $this->baseUrl . $this->getCallbackPath(),
            'response_type' => 'code',
            'scope'         => $this->providerConfig['scope'],
            'state'         => $state,
            'response_mode' => 'query',
        ]);

        return $authUrl . '?' . $params;
    }

    public function exchangeCodeWithProvider(string $code): ?array
    {
        $tenantId = $this->providerConfig['tenant_id'] ?? 'common';
        $tokenUrl = sprintf($this->providerConfig['token_url'], $tenantId);

        return $this->httpPost($tokenUrl, [
            'client_id'     => $this->providerConfig['client_id'],
            'client_secret' => $this->providerConfig['client_secret'],
            'code'          => $code,
            'redirect_uri'  => $this->baseUrl . $this->getCallbackPath(),
            'grant_type'    => 'authorization_code',
            'scope'         => $this->providerConfig['scope'],
        ]);
    }

    public function fetchUserInfoFromProvider(string $accessToken): ?array
    {
        $user = $this->httpGetWithToken('https://graph.microsoft.com/v1.0/me', $accessToken);

        $this->logger->error('Microsoft Graph /me response', [
            'response' => $user,
            'token_prefix' => substr($accessToken, 0, 20),
        ]);

        if (!$user || isset($user['error'])) {
            return null;
        }

        // Return in Google OAuth2 userinfo-compatible format
        return [
            'id'             => $user['id'] ?? '',
            'email'          => $user['mail'] ?? $user['userPrincipalName'] ?? '',
            'verified_email' => true,
            'name'           => $user['displayName'] ?? '',
            'given_name'     => $user['givenName'] ?? '',
            'family_name'    => $user['surname'] ?? '',
            'picture'        => '',
            'locale'         => $user['preferredLanguage'] ?? '',
            'provider'       => 'microsoft',
        ];
    }
}
