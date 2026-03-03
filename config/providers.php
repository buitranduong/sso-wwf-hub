<?php

return [
    'google' => [
        'client_id'     => getenv('GOOGLE_CLIENT_ID') ?: '',
        'client_secret' => getenv('GOOGLE_CLIENT_SECRET') ?: '',
        'auth_url'      => 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_url'     => 'https://oauth2.googleapis.com/token',
        'userinfo_url'  => 'https://www.googleapis.com/oauth2/v2/userinfo',
        'scope'         => 'openid email profile',
    ],
    'microsoft' => [
        'client_id'     => getenv('MICROSOFT_CLIENT_ID') ?: '',
        'client_secret' => getenv('MICROSOFT_CLIENT_SECRET') ?: '',
        'tenant_id'     => getenv('MICROSOFT_TENANT_ID') ?: 'common',
        'auth_url'      => 'https://login.microsoftonline.com/%s/oauth2/v2.0/authorize',
        'token_url'     => 'https://login.microsoftonline.com/%s/oauth2/v2.0/token',
        'scope'         => 'openid email profile User.Read',
    ],
];
