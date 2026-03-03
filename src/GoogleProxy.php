<?php

namespace SSO;

class GoogleProxy extends OAuthProxy
{
    protected function getProviderName(): string
    {
        return 'google';
    }

    protected function getCallbackPath(): string
    {
        return '/google/callback';
    }

    protected function buildAuthUrl(string $state): string
    {
        $params = http_build_query([
            'client_id'     => $this->providerConfig['client_id'],
            'redirect_uri'  => $this->baseUrl . $this->getCallbackPath(),
            'response_type' => 'code',
            'scope'         => $this->providerConfig['scope'],
            'state'         => $state,
            'access_type'   => 'offline',
            'prompt'        => 'consent',
        ]);

        return $this->providerConfig['auth_url'] . '?' . $params;
    }

    public function exchangeCodeWithProvider(string $code): ?array
    {
        return $this->httpPost($this->providerConfig['token_url'], [
            'client_id'     => $this->providerConfig['client_id'],
            'client_secret' => $this->providerConfig['client_secret'],
            'code'          => $code,
            'redirect_uri'  => $this->baseUrl . $this->getCallbackPath(),
            'grant_type'    => 'authorization_code',
        ]);
    }

    public function fetchUserInfoFromProvider(string $accessToken): ?array
    {
        $user = $this->httpGetWithToken($this->providerConfig['userinfo_url'], $accessToken);

        if (!$user || isset($user['error'])) {
            return null;
        }

        // Already in Google format, just ensure all fields exist
        return [
            'id'             => $user['id'] ?? '',
            'email'          => $user['email'] ?? '',
            'verified_email' => $user['verified_email'] ?? true,
            'name'           => $user['name'] ?? '',
            'given_name'     => $user['given_name'] ?? '',
            'family_name'    => $user['family_name'] ?? '',
            'picture'        => $user['picture'] ?? '',
            'locale'         => $user['locale'] ?? '',
            'provider'       => 'google',
        ];
    }
}
