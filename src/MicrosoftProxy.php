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
}
