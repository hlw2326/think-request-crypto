<?php

declare(strict_types=1);

namespace Hlw\Crypto;

use think\Request;

/**
 * 请求解密与验签工具（方案1：RSA + AES 工业级混合加解密架构）
 *
 * @class Crypto
 * @package Hlw\Crypto
 */
class Crypto
{
    /**
     * 方案1：RSA + AES 混合解密密文（一次一密，极速微秒级解析）
     *
     * 密文协议格式：[RSA加密的Key:IV].[AES加密的业务密文]
     *
     * @param string $cipher 密文字符串（两段式混合密文或明文 JSON）
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
            return is_array($rawJson) ? $rawJson : null;
        }

        // 2. 方案1：RSA + AES 混合解密解析（标准两段式：[RSA_KEY_IV].[AES_DATA]）
        if (!str_contains($cipher, '.')) {
            return null;
        }

        [$encKeyB64, $encDataB64] = explode('.', $cipher, 2);

        $key = $privateKey ?: (function_exists('config') ? (string) config('crypto.private_key') : (string) env('RSA_PRIVATE_KEY'));
        $key = str_replace(['\r\n', '\n'], "\n", trim($key));
        if ($key === '') {
            return null;
        }

        $rawEncKey = base64_decode($encKeyB64, true);
        if ($rawEncKey === false) {
            return null;
        }

        $decryptedSecret = '';
        $isKeyOk = openssl_private_decrypt($rawEncKey, $decryptedSecret, $key, OPENSSL_PKCS1_PADDING);
        if (!$isKeyOk || !str_contains($decryptedSecret, ':')) {
            return null;
        }

        [$aesKey, $aesIv] = explode(':', $decryptedSecret, 2);
        $rawEncData = base64_decode($encDataB64, true);
        if ($rawEncData === false) {
            return null;
        }

        $decryptedJson = openssl_decrypt($rawEncData, 'AES-128-CBC', $aesKey, OPENSSL_RAW_DATA, $aesIv);
        if ($decryptedJson === false || $decryptedJson === '') {
            return null;
        }

        $data = json_decode($decryptedJson, true);
        return is_array($data) ? $data : null;
    }

    /**
     * 方案1：RSA + AES 混合加密（一次一密，极速对称加密，单块 RSA 密约）
     *
     * @param array|string $data 待加密数据
     * @param ?string $publicKey RSA 公钥内容（缺省自动从 config 或 env 读取）
     * @return ?string 两段式点分隔 Base64 密文，加密失败返回 null
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

        // 1. 动态生成 16 字节随机密钥与 16 字节 IV
        $aesKey = bin2hex(random_bytes(8));
        $aesIv  = bin2hex(random_bytes(8));

        // 2. RSA 单块加密对称密钥对（仅 33 字节，绝无分段负担）
        $encryptedKey = '';
        $isKeyOk = openssl_public_encrypt("{$aesKey}:{$aesIv}", $encryptedKey, $key, OPENSSL_PKCS1_PADDING);
        if (!$isKeyOk) {
            return null;
        }

        // 3. AES-128-CBC 高性能加密业务数据
        $encryptedData = openssl_encrypt($raw, 'AES-128-CBC', $aesKey, OPENSSL_RAW_DATA, $aesIv);
        if ($encryptedData === false) {
            return null;
        }

        return base64_encode($encryptedKey) . '.' . base64_encode($encryptedData);
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
