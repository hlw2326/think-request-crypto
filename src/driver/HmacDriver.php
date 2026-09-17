<?php

declare(strict_types=1);

namespace Hlw\Crypto\driver;

use think\Request;

/**
 * HTTP Header HMAC-SHA256 签名驱动
 *
 * @class HmacDriver
 * @package Hlw\Crypto\driver
 */
class HmacDriver extends AbstractDriver
{
    /**
     * 计算签名
     */
    public function sign(string $content, array $options = []): string
    {
        $secret = (string)($options['secret'] ?? $this->getConfig('secret', ''));
        $algo = (string)($options['algo'] ?? $this->getConfig('algo', 'sha256'));
        return hash_hmac($algo, $content, $secret);
    }

    /**
     * 校验请求合法性
     */
    public function verify(Request $request): array
    {
        $secret = (string)$this->getConfig('secret', '');
        if ($secret === '' || !$this->getConfig('enabled', true)) {
            return [true, '', []];
        }

        $signature = (string)($request->header('x-signature', '') ?: $request->param('sign', ''));
        if ($signature === '') {
            return [false, '请求缺少 HMAC 签名 (x-signature)', []];
        }

        $timestamp = (int)($request->header('x-timestamp', 0) ?: $request->param('t', 0));
        [$timeOk, $timeMsg] = $this->checkTimestamp($timestamp);
        if (!$timeOk) {
            return [false, $timeMsg, []];
        }

        $nonce = (string)($request->header('x-nonce', '') ?: $request->param('nonce', ''));
        $bodyHash = md5((string)$request->getContent());
        $url = $request->baseUrl();
        $method = strtoupper($request->method());

        $stringToSign = "{$method}\n{$url}\n{$timestamp}\n{$nonce}\n{$bodyHash}";
        $expected = $this->sign($stringToSign);

        if (!hash_equals($expected, $signature)) {
            return [false, 'HMAC 签名校验失败', []];
        }

        return [true, '', []];
    }

    /**
     * 加密数据
     */
    public function encrypt(mixed $data): string
    {
        $content = is_string($data) ? $data : (string)json_encode($data, JSON_UNESCAPED_UNICODE);
        return $this->sign($content);
    }

    /**
     * 解密数据
     */
    public function decrypt(string $ciphertext): mixed
    {
        return $ciphertext;
    }
}
