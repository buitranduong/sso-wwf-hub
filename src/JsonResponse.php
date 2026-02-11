<?php

namespace SSO;

class JsonResponse
{
    public static function error(int $httpCode, string $error, string $message): never
    {
        http_response_code($httpCode);
        header('Content-Type: application/json');
        echo json_encode([
            'error'   => $error,
            'message' => $message,
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    public static function success(array $data, int $httpCode = 200): never
    {
        http_response_code($httpCode);
        header('Content-Type: application/json');
        echo json_encode($data, JSON_UNESCAPED_SLASHES);
        exit;
    }
}
