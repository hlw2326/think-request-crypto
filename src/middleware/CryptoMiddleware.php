<?php

declare(strict_types=1);

namespace Hlw\Crypto\middleware;

use Closure;
use Hlw\Crypto\Crypto;
use think\Request;
use think\Response;

/**
 * 请求解密与验签中间件
 *
 * @class CryptoMiddleware
 * @package Hlw\Crypto\middleware
 */
class CryptoMiddleware
{
    /**
     * 中间件调度处理
     *
     * @param Request $request
     * @param Closure $next
     * @return Response
     */
    public function handle(Request $request, Closure $next): Response
    {
        [$status, $message, $context] = Crypto::verify($request);
        if (!$status) {
            return json([
                'code' => 0,
                'msg'  => $message ?: '请求校验失败',
                'data' => null,
            ], 401);
        }

        // 绑定解析后的设备与上下文信息到请求对象
        $request->clientContext = $context;
        if (!empty($context['token'])) {
            $request->clientToken = (string) $context['token'];
        }

        return $next($request);
    }
}
