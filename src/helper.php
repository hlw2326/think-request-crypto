<?php

declare(strict_types=1);

use Hlw\Crypto\Crypto;
use think\Request;

// 注册向下兼容别名
if (!class_exists('crypto\Crypto', false)) {
    class_alias(Crypto::class, 'crypto\Crypto');
}

if (!function_exists('verify_sign')) {
    /**
     * 校验请求合法性并解密上下文
     *
     * @param ?Request $request 请求实例（未传则自动获取当前请求）
     * @return array{0: bool, 1: string, 2: array} [状态, 错误信息, 设备与Token上下文]
     */
    function verify_sign(?Request $request = null): array
    {
        $req = $request ?: (function_exists('request') ? request() : (function_exists('app') ? app('request') : null));
        if ($req === null) {
            return [false, '无法获取请求实例', []];
        }
        return Crypto::verify($req);
    }
}

if (!function_exists('encrypt_response')) {
    /**
     * 加密响应体
     *
     * @param mixed $data 待响应数据
     * @return mixed
     */
    function encrypt_response(mixed $data): mixed
    {
        return $data ?: [];
    }
}

if (!function_exists('sign')) {
    /**
     * 构建请求签名
     *
     * @param string $content 签名内容
     * @param array $options 签名选项
     * @return string
     */
    function sign(string $content, array $options = []): string
    {
        return Crypto::sign($content, $options);
    }
}
