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
}
