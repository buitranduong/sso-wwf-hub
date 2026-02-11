<?php

require __DIR__ . '/../vendor/autoload.php';

use SSO\GoogleProxy;
use SSO\MicrosoftProxy;
use SSO\RedisState;
use SSO\Logger;
use SSO\JsonResponse;

$logger = new Logger();

try {
    $stateStore = new RedisState();
} catch (\RuntimeException $e) {
    $logger->error('Redis connection failed', ['error' => $e->getMessage()]);
    JsonResponse::error(503, 'service_unavailable', 'State store is unavailable');
}

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

try {
    switch ($path) {
        case '/google/auth':
            (new GoogleProxy($stateStore, $logger))->auth();
            break;
        case '/google/callback':
            (new GoogleProxy($stateStore, $logger))->callback();
            break;

        case '/microsoft/auth':
            (new MicrosoftProxy($stateStore, $logger))->auth();
            break;
        case '/microsoft/callback':
            (new MicrosoftProxy($stateStore, $logger))->callback();
            break;

        case '/health':
            JsonResponse::success(['status' => 'ok']);
            break;

        default:
            JsonResponse::error(404, 'not_found', 'Endpoint not found');
    }
} catch (\Throwable $e) {
    $logger->error('Unhandled exception', [
        'exception' => get_class($e),
        'message'   => $e->getMessage(),
        'path'      => $path,
    ]);
    JsonResponse::error(500, 'internal_error', 'An unexpected error occurred');
}
