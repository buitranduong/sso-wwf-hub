<?php

namespace SSO;

class RedisState
{
    private \Redis $redis;

    public function __construct()
    {
        $this->redis = new \Redis();

        $host = getenv('REDIS_HOST') ?: '127.0.0.1';
        $port = (int) (getenv('REDIS_PORT') ?: 6379);
        $password = getenv('REDIS_PASSWORD') ?: null;

        if (!$this->redis->connect($host, $port, 5.0)) {
            throw new \RuntimeException('Failed to connect to Redis');
        }

        if ($password) {
            if (!$this->redis->auth($password)) {
                throw new \RuntimeException('Redis authentication failed');
            }
        }
    }

    // --- OAuth State (CSRF) ---

    public function set(string $state, array $data, int $ttl = 300): void
    {
        $this->redis->setex("oauth_state:$state", $ttl, json_encode($data));
    }

    public function get(string $state): ?array
    {
        $data = $this->redis->get("oauth_state:$state");
        return $data ? json_decode($data, true) : null;
    }

    public function delete(string $state): void
    {
        $this->redis->del("oauth_state:$state");
    }

    // --- Code Mapping (wrapped_code → provider + original_code) ---

    public function setCodeMapping(string $wrappedCode, array $data, int $ttl = 300): void
    {
        $this->redis->setex("sso_code:$wrappedCode", $ttl, json_encode($data));
    }

    public function getCodeMapping(string $wrappedCode): ?array
    {
        $data = $this->redis->get("sso_code:$wrappedCode");
        return $data ? json_decode($data, true) : null;
    }

    public function deleteCodeMapping(string $wrappedCode): void
    {
        $this->redis->del("sso_code:$wrappedCode");
    }

    // --- Token → Provider mapping (access_token → provider name) ---

    public function setTokenProvider(string $accessToken, array $data, int $ttl = 3600): void
    {
        // Hash the token for security (don't store raw access tokens as Redis keys)
        $key = hash('sha256', $accessToken);
        $this->redis->setex("sso_token:$key", $ttl, json_encode($data));
    }

    public function getTokenProvider(string $accessToken): ?array
    {
        $key = hash('sha256', $accessToken);
        $data = $this->redis->get("sso_token:$key");
        return $data ? json_decode($data, true) : null;
    }
}
