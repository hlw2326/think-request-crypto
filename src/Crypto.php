<?php

declare(strict_types=1);

namespace Hlw\Crypto;

use think\Request;

/**
 * 请求解密与验签工具
 *
 * @class Crypto
 * @package Hlw\Crypto
 */
class Crypto
{
    /**
     * RSA-2048 私钥分段解密密文
     *
     * @param string $cipher 密文字符串（支持点分隔多段 Base64、连续 256 字节 Base64、或明文 JSON）
     * @param ?string $privateKey RSA 私钥内容（缺省自动从 config 或 env 读取）
     * @return ?array 解密后的数据字典，解密失败返回 null
     */
    public static function decrypt(string $cipher, ?string $privateKey = null): ?array
    {
        $cipher = trim($cipher);
        if ($cipher === '') {
            return null;
        }

        // 1. 若直接为明文 JSON 结构
        if (str_starts_with($cipher, '{') || str_starts_with($cipher, '[')) {
            $rawJson = json_decode($cipher, true);
            if (is_array($rawJson)) {
                return $rawJson;
            }
        }

        // 2. 若为 URL 编码的 JSON
        if (str_contains($cipher, '%')) {
            $decodedUrl = rawurldecode($cipher);
            if (str_starts_with($decodedUrl, '{') || str_starts_with($decodedUrl, '[')) {
                $rawJson = json_decode($decodedUrl, true);
                if (is_array($rawJson)) {
                    return $rawJson;
                }
            }
        }

        // 3. 读取 RSA 私钥并格式化换行
        $key = $privateKey ?: (function_exists('config') ? (string) config('crypto.private_key') : (string) env('RSA_PRIVATE_KEY'));
        $key = str_replace(['\r\n', '\n'], "\n", trim($key));
        if ($key === '') {
            return null;
        }

        // 4. 解析分块（支持点分隔 Base64 或连续 256 字节块）
        $isRawBytes = false;
        if (str_contains($cipher, '.')) {
            $chunks = explode('.', $cipher);
        } else {
            $rawAll = base64_decode($cipher, true);
            if ($rawAll === false) {
                $rawAll = base64_decode(str_replace(' ', '+', $cipher), true);
            }
            if ($rawAll !== false && strlen($rawAll) >= 256 && strlen($rawAll) % 256 === 0) {
                $chunks = str_split($rawAll, 256);
                $isRawBytes = true;
            } else {
                $chunks = [$cipher];
            }
        }

        $result = '';

        foreach ($chunks as $chunk) {
            if ($isRawBytes) {
                $rawChunk = $chunk;
            } else {
                $rawChunk = base64_decode($chunk, true);
                if ($rawChunk === false) {
                    $rawChunk = base64_decode(str_replace(' ', '+', $chunk), true);
                }
            }
            if ($rawChunk === false || $rawChunk === '') {
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
     * RSA-2048 公钥分段加密（117 字节/块，PKCS1 Padding，生成点分隔 Base64 串）
     *
     * @param array|string $data 待加密数据
     * @param ?string $publicKey RSA 公钥内容（缺省自动从 config 或 env 读取）
     * @return ?string 点分隔的 Base64 密文，加密失败返回 null
     */
    public static function encrypt(array|string $data, ?string $publicKey = null): ?string
    {
        $raw = is_array($data) ? json_encode($data, JSON_UNESCAPED_UNICODE) : (string) $data;
        if ($raw === '') {
            return '';
        }

        $key = $publicKey ?: (function_exists('config') ? (string) config('crypto.public_key') : (string) env('RSA_PUBLIC_KEY'));
        $key = str_replace(['\r\n', '\n'], "\n", trim($key));
        if ($key === '') {
            return null;
        }

        $chunks = str_split($raw, 117);
        $encryptedChunks = [];

        foreach ($chunks as $chunk) {
            $encrypted = '';
            $isOk = openssl_public_encrypt($chunk, $encrypted, $key, OPENSSL_PKCS1_PADDING);
            if (!$isOk) {
                return null;
            }
            $encryptedChunks[] = base64_encode($encrypted);
        }

        return implode('.', $encryptedChunks);
    }

    /**
     * 计算 SHA256 请求防篡改签名
     *
     * @param string $content 规范化业务参数排序串
     * @param array $options 包含 timestamp, nonce, context, secret 的配置项
     * @return string
     */
    public static function sign(string $content, array $options = []): string
    {
        $timestamp = (string) ($options['timestamp'] ?? time());
        $nonce = (string) ($options['nonce'] ?? '');
        $context = (string) ($options['context'] ?? '');
        $secret = (string) ($options['secret'] ?? (function_exists('config') ? config('crypto.secret') : (env('CRYPTO_SIGN_SECRET') ?: env('CRYPTO_SECRET'))));

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
            $context = (string) ($request->header('x-client-context', '') ?: $request->param('context', ''));
            $contextData = [];
            if ($context !== '') {
                $contextData = static::decrypt($context) ?: (json_decode(rawurldecode($context), true) ?: []);
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

        // 时钟防重放校验（默认 300 秒）
        $expire = function_exists('config') ? (int) config('crypto.expire', 300) : 300;
        $timeVal = strlen($timestamp) > 10 ? (float) $timestamp / 1000 : (float) $timestamp;
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
        $secret = function_exists('config') ? (string) config('crypto.secret') : (string) (env('CRYPTO_SIGN_SECRET') ?: env('CRYPTO_SECRET'));
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
