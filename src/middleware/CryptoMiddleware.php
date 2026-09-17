<?php

declare(strict_types=1);

namespace Hlw\Crypto\middleware;

use Closure;
use Hlw\Crypto\Crypto;
use think\Request;
use think\Response;

/**
 * 请求加密与验签中间件
 *
 * @class CryptoMiddleware
 * @package Hlw\Crypto\middleware
 */
class CryptoMiddleware
{
    /**
     * 中间件处理入口
     *
     * @param Request $request
     * @param Closure $next
     * @return Response
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
        } catch (\Throwable $e) {
            return json([
                'code' => 401,
                'info' => $e->getMessage(),
                'data' => [],
            ], 401);
        }

        return $next($request);
    }
}
