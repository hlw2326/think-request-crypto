<?php

declare(strict_types=1);

namespace Hlw\Crypto\middleware;

use Closure;
use Hlw\Crypto\Crypto;
use think\Request;
use think\Response;

/**
 * 请求安全中间件
 */
class CryptoMiddleware
{
    /**
 * 请求安全中间件
 */
    public function handle(Request $request, Closure $next): Response
    {
        [$valid, $message, $data] = Crypto::verify($request);
        if (!$valid) {
            return json([
                'code' => 401,
                'info' => $message ?: '请求未通过安全校验',
                'data' => [],
            ], 401);
        }

        // 校验通过后，自动将解密参数注入 Request
        try {
            $request = Crypto::handleRequest($request);
        } catch (\Throwable $error) {
            return json([
                'code' => 401,
                'info' => $error->getMessage(),
                'data' => [],
            ], 401);
        }

        return $next($request);
    }
}
