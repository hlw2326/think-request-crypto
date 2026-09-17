<?php

declare(strict_types=1);

namespace Hlw\Crypto\driver;

use think\Request;

/**
 * 非对称驱动
 *
 * @class RsaDriver
 * @package Hlw\Crypto\driver
 */
class RsaDriver extends AbstractDriver
{
    /**
     * 加密数据体
     *
     * @param mixed $data 待加密数据
     * @return string 加密后密文
     */
    public function encrypt(mixed $data): string
    {
        $clientKey = (string) $this->getConfig('client_public_key');
        if ($clientKey === '' || empty($data)) {
            return '';
        }

        $json = is_string($data) ? $data : json_encode($data, JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            return '';
        }

        $aesKey = random_bytes(32);
        $aesIv = random_bytes(16);
        $encPayload = openssl_encrypt($json, 'AES-256-CBC', $aesKey, OPENSSL_RAW_DATA, $aesIv);
        if ($encPayload === false) {
            return '';
        }

        $keyBlock = $aesKey . $aesIv;
        $encKey = '';
        $isOk = openssl_public_encrypt($keyBlock, $encKey, $clientKey, OPENSSL_PKCS1_OAEP_PADDING);
        if (!$isOk) {
            return '';
        }

        return base64_encode($encKey) . '.' . base64_encode($encPayload);
    }

    /**
     * 解密密文体
     *
     * @param string $ciphertext 密文字符串
     * @return mixed 解密后数据
     */
    public function decrypt(string $ciphertext): mixed
    {
        if ($ciphertext === '' || !str_contains($ciphertext, '.')) {
            return null;
        }

        $parts = explode('.', $ciphertext, 2);
        if (count($parts) !== 2) {
            return null;
        }
        [$encKey, $encPayload] = $parts;

        $privateKey = (string) $this->getConfig('private_key');
        if ($privateKey === '') {
            return null;
        }

        $keyBlock = '';
        $isOk = openssl_private_decrypt(base64_decode($encKey), $keyBlock, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
        if (!$isOk || strlen($keyBlock) < 48) {
            return null;
        }

        $aesKey = substr($keyBlock, 0, 32);
        $aesIv = substr($keyBlock, 32, 16);

        $json = openssl_decrypt(base64_decode($encPayload), 'AES-256-CBC', $aesKey, OPENSSL_RAW_DATA, $aesIv);
        if ($json === false || $json === '') {
            return null;
        }

        $result = json_decode($json, true);
        return is_array($result) ? $result : $json;
    }

    /**
     * 递归序列化
     *
     * @param mixed $data 待排序数据
     * @return string 序列化文本
     */
    public function sortString(mixed $data): string
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
            $items = array_map([$this, 'sortString'], $data);
            return '[' . implode(',', $items) . ']';
        }

        ksort($data);
        $parts = [];
        foreach ($data as $key => $value) {
            if ($value !== null && !is_resource($value)) {
                $valStr = $this->sortString($value);
                $parts[] = "{$key}={$valStr}";
            }
        }
        return implode('&', $parts);
    }

    /**
     * 计算签名值
     *
     * @param string $content 签名原文串
     * @param array $options 附加选项集
     * @return string 签名哈希值
     */
    public function sign(string $content, array $options = []): string
    {
        $timestamp = (string) ($options['timestamp'] ?? time());
        $nonce = (string) ($options['nonce'] ?? '');
        $secret = (string) ($options['secret'] ?? $this->getConfig('secret', ''));
        $raw = "ts={$timestamp}&nonce={$nonce}&data={$content}&key={$secret}";
        return hash('sha256', $raw);
    }

    /**
     * 校验合法性
     *
     * @param Request $request 请求实例项
     * @return array{0: bool, 1: string, 2: mixed} 校验结果组
     */
    public function verify(Request $request): array
    {
        $isEnabled = (bool) $this->getConfig('enabled', true);
        if (!$isEnabled) {
            return [true, '', []];
        }

        $clientSign = (string) $request->header('x-client-sign', '');
        $timestamp = (string) $request->header('x-client-timestamp', '');
        $nonce = (string) $request->header('x-client-nonce', '');

        if ($clientSign === '' || $timestamp === '' || $nonce === '') {
            return [false, '非法网络请求', []];
        }

        $timeMs = floatval($timestamp);
        $currentMs = microtime(true) * 1000;
        $maxSkew = ((int) $this->getConfig('expire', 300)) * 1000;

        if (abs($currentMs - $timeMs) > $maxSkew) {
            return [false, '请求时钟超时', []];
        }

        if ($request->isGet()) {
            $params = $request->get();
        } else {
            $rawInput = (string) $request->getInput();
            $jsonData = json_decode($rawInput, true);
            $params = is_array($jsonData) ? $jsonData : ($request->post() ?: []);
        }

        $paramStr = $this->sortString($params ?: []);
        $secret = (string) $this->getConfig('secret', '');
        $rawStr = "ts={$timestamp}&nonce={$nonce}&data={$paramStr}&key={$secret}";
        $expectedSign = hash('sha256', $rawStr);

        if (!hash_equals(strtolower($expectedSign), strtolower($clientSign))) {
            return [false, '签名校验失败', []];
        }

        // 解密设备上下文
        $cipherContext = (string) $request->header('x-client-context', '');
        if ($cipherContext === '') {
            $cipherContext = (string) $request->get('d', '');
        }

        $contextData = [];
        if ($cipherContext !== '') {
            $decrypted = $this->decrypt($cipherContext);
            if (is_array($decrypted)) {
                $contextData = $decrypted;
            }
        }

        return [true, '', $contextData];
    }

    /**
     * 处理请求项
     *
     * @param Request $request 请求实例项
     * @return Request
     */
    public function handleRequest(Request $request): Request
    {
        [$isValid, $message, $data] = $this->verify($request);
        if (!$isValid) {
            throw new RuntimeException($message ?: '非法网络请求', 401);
        }

        if (!empty($data) && is_array($data)) {
            $request->withGet(array_merge($request->get(), ['device_context' => $data]));
        }

        return $request;
    }
}
