# SSO Proxy Service

Lightweight OAuth 2.0 proxy service hoat dong nhu middleware trung gian giua cac web application va OAuth provider (Google, Microsoft). Service nay **chi proxy authorization code**, khong exchange token - viec do client app tu thuc hien.

## Architecture

```
Client App                    SSO Proxy                    OAuth Provider
    |                             |                             |
    |-- GET /{provider}/auth ---->|                             |
    |   ?client_id=X              |                             |
    |   &redirect_uri=Y           |                             |
    |                             |-- store state in Redis -->  |
    |                             |                             |
    |                             |-- 302 Redirect ------------>|
    |                             |   (to OAuth login page)     |
    |                             |                             |
    |                             |<-- callback with code ------|
    |                             |   ?code=Z&state=S           |
    |                             |                             |
    |                             |-- validate state (Redis) -> |
    |                             |-- delete state (one-time) ->|
    |                             |                             |
    |<-- 302 Redirect ------------|                             |
    |   redirect_uri?code=Z       |                             |
```

## Supported Providers

| Provider  | Auth Endpoint            | Callback Endpoint            |
|-----------|--------------------------|------------------------------|
| Google    | `GET /google/auth`       | `GET /google/callback`       |
| Microsoft | `GET /microsoft/auth`    | `GET /microsoft/callback`    |

## Quick Start

### 1. Clone va cau hinh

```bash
cp .env.example .env
# Edit .env voi credentials cua ban
```

### 2. Dang ky OAuth App

**Google:**
1. Vao [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Tao OAuth 2.0 Client ID
3. Them Authorized redirect URI: `http://localhost:8080/google/callback`
4. Copy Client ID va Client Secret vao `.env`

**Microsoft (Azure AD):**
1. Vao [Azure Portal > App registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Tao app registration moi
3. Them Redirect URI (Web): `http://localhost:8080/microsoft/callback`
4. Tao Client Secret trong "Certificates & secrets"
5. Copy Application (client) ID, Directory (tenant) ID, va Client Secret vao `.env`

### 3. Dang ky client app

Edit `config/clients.php` de them client application cua ban:

```php
return [
    'my_app' => [
        'redirect_uris' => [
            'https://my-app.com/auth/callback',
        ],
    ],
];
```

### 4. Chay service

```bash
docker compose up -d
```

Kiem tra health:
```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

## API Endpoints

### `GET /{provider}/auth`

Bat dau OAuth flow. Redirect user den OAuth provider.

**Parameters:**

| Param          | Required | Description                                         |
|----------------|----------|-----------------------------------------------------|
| `client_id`    | Yes      | Client ID da dang ky trong `config/clients.php`     |
| `redirect_uri` | Yes      | URI nhan callback, phai nam trong whitelist cua client |

**Response:** HTTP 302 redirect den OAuth provider

**Errors:**
- `400 invalid_client` - client_id khong ton tai
- `400 invalid_redirect_uri` - redirect_uri khong nam trong whitelist

**Example:**
```bash
curl -v "http://localhost:8080/google/auth?client_id=my_app&redirect_uri=https://my-app.com/auth/callback"
```

### `GET /{provider}/callback`

OAuth provider goi endpoint nay sau khi user xac thuc. Service se redirect ve client app voi authorization code.

**Parameters (tu OAuth provider):**

| Param   | Description              |
|---------|--------------------------|
| `code`  | Authorization code       |
| `state` | State token de chong CSRF |

**Response:** HTTP 302 redirect ve `redirect_uri?code={code}`

**Errors:**
- `400 invalid_request` - Thieu state hoac code
- `400 invalid_state` - State token khong hop le hoac het han
- `502 provider_error` - OAuth provider tra ve loi

### `GET /health`

Health check endpoint.

**Response:** `{"status":"ok"}`

## Configuration

### Environment Variables

| Variable                 | Required | Default       | Description                          |
|--------------------------|----------|---------------|--------------------------------------|
| `GOOGLE_CLIENT_ID`       | Yes      | -             | Google OAuth Client ID               |
| `GOOGLE_CLIENT_SECRET`   | Yes      | -             | Google OAuth Client Secret           |
| `MICROSOFT_CLIENT_ID`    | Yes*     | -             | Microsoft OAuth Application ID       |
| `MICROSOFT_CLIENT_SECRET`| Yes*     | -             | Microsoft OAuth Client Secret        |
| `MICROSOFT_TENANT_ID`    | No       | `common`      | Azure AD Tenant ID                   |
| `REDIS_HOST`             | No       | `redis`       | Redis server hostname                |
| `REDIS_PORT`             | No       | `6379`        | Redis server port                    |
| `REDIS_PASSWORD`         | Yes      | -             | Redis authentication password        |
| `APP_BASE_URL`           | Yes      | `http://localhost:8080` | Public URL cua SSO service  |
| `APP_LOG_LEVEL`          | No       | `info`        | Log level: debug, info, warning, error |

*Required neu su dung Microsoft OAuth

### Client Registration (`config/clients.php`)

Moi client app phai duoc dang ky voi danh sach redirect_uri cho phep:

```php
return [
    'client_id_here' => [
        'redirect_uris' => [
            'https://app.example.com/auth/google/callback',
            'https://app.example.com/auth/microsoft/callback',
        ],
    ],
];
```

## Security

### CSRF Protection
- Moi auth request tao mot `state` token ngau nhien (32 hex chars, cryptographically secure)
- State luu trong Redis voi TTL 5 phut
- State chi su dung mot lan (xoa ngay sau khi validate)

### Redirect URI Whitelist
- `redirect_uri` phai khop chinh xac voi danh sach da dang ky trong `config/clients.php`
- Ngan chan Open Redirect attack

### Redis Security
- Redis yeu cau password authentication
- Redis khong expose port ra ngoai (chi internal Docker network)

### Provider Isolation
- State token luu ten provider, ngan chan cross-provider state confusion attack

## Adding a New OAuth Provider

1. Tao class moi extend `OAuthProxy`:

```php
<?php
namespace SSO;

class NewProviderProxy extends OAuthProxy
{
    protected function getProviderName(): string
    {
        return 'newprovider';
    }

    protected function getCallbackPath(): string
    {
        return '/newprovider/callback';
    }

    protected function buildAuthUrl(string $state): string
    {
        $params = http_build_query([
            'client_id'     => $this->providerConfig['client_id'],
            'redirect_uri'  => $this->baseUrl . $this->getCallbackPath(),
            'response_type' => 'code',
            'scope'         => $this->providerConfig['scope'],
            'state'         => $state,
        ]);

        return $this->providerConfig['auth_url'] . '?' . $params;
    }
}
```

2. Them config vao `config/providers.php`
3. Them routes vao `public/index.php`
4. Dang ky callback URL voi OAuth provider

## Tech Stack

- **PHP 8.2** + Apache
- **Redis 7** - Luu tru state token tam thoi
- **Docker Compose** - Orchestration

## Project Structure

```
sso-php-redis/
├── public/
│   ├── index.php          # Router + entry point
│   └── .htaccess          # Apache URL rewriting
├── src/
│   ├── OAuthProxy.php     # Abstract base class
│   ├── GoogleProxy.php    # Google OAuth implementation
│   ├── MicrosoftProxy.php # Microsoft OAuth implementation
│   ├── RedisState.php     # Redis state management
│   ├── Logger.php         # Structured JSON logging
│   └── JsonResponse.php   # JSON response helper
├── config/
│   ├── providers.php      # OAuth provider configurations
│   └── clients.php        # Registered client applications
├── Dockerfile
├── docker-compose.yml
├── composer.json
├── .env.example
└── .gitignore
```

## Logging

Logs duoc ghi ra stderr duoi dang JSON (hien thi qua `docker compose logs`):

```json
{"timestamp":"2026-02-11T10:30:00+07:00","level":"info","message":"Redirecting to OAuth provider","context":{"provider":"google","client_id":"my_app"}}
```

Xem logs:
```bash
docker compose logs -f sso
```

## Development

```bash
# Build va chay
docker compose up -d --build

# Xem logs
docker compose logs -f sso

# Restart
docker compose restart sso

# Dung service
docker compose down
```
