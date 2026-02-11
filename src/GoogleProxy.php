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
}
