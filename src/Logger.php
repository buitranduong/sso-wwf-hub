<?php

namespace SSO;

class Logger
{
    private string $minLevel;

    private const LEVELS = [
        'debug' => 0,
        'info' => 1,
        'warning' => 2,
        'error' => 3,
    ];

    public function __construct(?string $minLevel = null)
    {
        $this->minLevel = $minLevel ?? (getenv('APP_LOG_LEVEL') ?: 'info');
    }

    public function log(string $level, string $message, array $context = []): void
    {
        if ((self::LEVELS[$level] ?? 0) < (self::LEVELS[$this->minLevel] ?? 0)) {
            return;
        }

        $entry = json_encode([
            'timestamp' => date('c'),
            'level'     => $level,
            'message'   => $message,
            'context'   => $context ?: new \stdClass(),
        ], JSON_UNESCAPED_SLASHES);

        error_log($entry);
    }

    public function info(string $msg, array $ctx = []): void
    {
        $this->log('info', $msg, $ctx);
    }

    public function error(string $msg, array $ctx = []): void
    {
        $this->log('error', $msg, $ctx);
    }

    public function warning(string $msg, array $ctx = []): void
    {
        $this->log('warning', $msg, $ctx);
    }

    public function debug(string $msg, array $ctx = []): void
    {
        $this->log('debug', $msg, $ctx);
    }
}
