<?php

declare(strict_types=1);

namespace Hlw\Crypto;

use think\Request;

require_once __DIR__ . '/helper.php';

/**
 * 请求解密与验签工具
 *
 * @class Crypto
 * @package Hlw\Crypto
 */
class Crypto
{
    /**
     * RSA 私钥分段解密密文
     *
     * @param string $cipher 以点分隔的 Base64 密文段
     * @param ?string $privateKey RSA 私钥内容
     * @return ?array 解密后的数据字典
     */
    public static function decrypt(string $cipher, ?string $privateKey = null): ?array
    {
        if ($cipher === '') {
            return null;
        }

        $key = $privateKey ?: (function_exists('config') ? (string) config('crypto.private_key') : (string) env('RSA_PRIVATE_KEY'));
        $key = str_replace(['\r\n', '\n'], "\n", trim($key));
        if ($key === '') {
            return null;
        }

        $chunks = explode('.', $cipher);
        $result = '';

        foreach ($chunks as $chunk) {
            $rawChunk = base64_decode($chunk, true);
            if ($rawChunk === false) {
                return null;
            }

            $decrypted = '';
            $isOk = openssl_private_decrypt($rawChunk, $decrypted, $key, OPENSSL_PKCS1_PADDING);
            if (!$isOk) {
                return null;
            }

            $result .= $decrypted;
        }

        $decoded = json_decode($result, true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * 计算 SHA256 签名
     *
     * @param string $content 规范化业务参数串
     * @param array $options 包含 timestamp, nonce, context, secret 的配置项
     * @return string
     */
    public static function sign(string $content, array $options = []): string
    {
        $timestamp = (string) ($options['timestamp'] ?? time());
        $nonce = (string) ($options['nonce'] ?? '');
        $context = (string) ($options['context'] ?? '');
        $secret = (string) ($options['secret'] ?? (function_exists('config') ? config('crypto.secret') : env('CRYPTO_SIGN_SECRET')));

        $raw = "ts={$timestamp}&nonce={$nonce}&context={$context}&data={$content}&key={$secret}";
        return hash('sha256', $raw);
    }

    /**
     * 校验请求合法性并解密上下文
     *
     * @param Request $request 当前请求实例
     * @return array{0: bool, 1: string, 2: array} [状态, 错误信息, 设备与Token上下文]
     */
    public static function verify(Request $request): array
    {
        $enabled = function_exists('config') ? (bool) config('crypto.enabled', true) : true;
        if (!$enabled) {
            $context = (string) $request->header('x-client-context', '');
            $contextData = [];
            if ($context !== '') {
                $contextData = static::decrypt($context) ?: (json_decode(urldecode($context), true) ?: []);
            }
            return [true, '', is_array($contextData) ? $contextData : []];
        }

        $sign = (string) $request->header('x-client-sign', '');
        $timestamp = (string) $request->header('x-client-timestamp', '');
        $nonce = (string) $request->header('x-client-nonce', '');
        $context = (string) $request->header('x-client-context', '');

        if ($sign === '' || $timestamp === '' || $nonce === '' || $context === '') {
            return [false, '非法网络请求', []];
        }

        // 时钟防重放校验（默认300秒）
        $expire = function_exists('config') ? (int) config('crypto.expire', 300) : 300;
        $timeVal = strlen($timestamp) > 10 ? floatval($timestamp) / 1000 : floatval($timestamp);
        if (abs(time() - $timeVal) > $expire) {
            return [false, '请求时钟超时', []];
        }

        // 规范化业务参数
        if ($request->isGet()) {
            $params = $request->get();
        } else {
            $input = (string) $request->getInput();
            $json = json_decode($input, true);
            $params = is_array($json) ? $json : ($request->post() ?: []);
        }

        $paramStr = static::sortString($params ?: []);
        $secret = function_exists('config') ? (string) config('crypto.secret') : (string) env('CRYPTO_SIGN_SECRET');
        $expected = static::sign($paramStr, [
            'timestamp' => $timestamp,
            'nonce'     => $nonce,
            'context'   => $context,
            'secret'    => $secret,
        ]);

        if (!hash_equals(strtolower($expected), strtolower($sign))) {
            return [false, '签名校验失败', []];
        }

        // 解密设备与 Token 上下文
        $contextData = static::decrypt($context);
        if ($contextData === null) {
            return [false, '凭证解密失败', []];
        }

        return [true, '', $contextData];
    }

    /**
     * 递归规范化参数排序串
     *
     * @param mixed $data
     * @return string
     */
    public static function sortString(mixed $data): string
    {
        if ($data === null || $data === '' || $data === []) {
            return '';
        }
        if (is_bool($data)) {
            return $data ? 'true' : 'false';
        }
        if (!is_array($data)) {
            return (string) $data;
        }

        if (array_keys($data) === range(0, count($data) - 1)) {
            $items = array_map([static::class, 'sortString'], $data);
            return '[' . implode(',', $items) . ']';
        }

        ksort($data);
        $parts = [];
        foreach ($data as $key => $value) {
            if ($value !== null && !is_resource($value)) {
                $val = static::sortString($value);
                $parts[] = "{$key}={$val}";
            }
        }
        return implode('&', $parts);
    }
}