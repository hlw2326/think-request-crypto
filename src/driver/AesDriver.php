<?php

declare(strict_types=1);

namespace Hlw\Crypto\driver;

use think\Request;

/**
 * AES-128/256-CBC 对称报文加解密驱动
 *
 * @class AesDriver
 * @package Hlw\Crypto\driver
 */
class AesDriver extends AbstractDriver
{
    /**
     * 获取加密算法
     */
    protected function getCipher(): string
    {
        return (string)$this->getConfig('cipher', 'AES-128-CBC');
    }

    /**
     * 获取加密密钥
     */
    protected function getKey(): string
    {
        $key = (string)$this->getConfig('key', '');
        $cipher = strtoupper($this->getCipher());
        if (str_contains($cipher, '128')) {
            return substr(str_pad($key, 16, "\0"), 0, 16);
        }
        return substr(str_pad($key, 32, "\0"), 0, 32);
    }

    /**
     * 获取初始向量 IV
     */
    protected function getIv(): string
    {
        $iv = (string)$this->getConfig('iv', '');
        return substr(str_pad($iv, 16, "\0"), 0, 16);
    }

    /**
     * 加密数据
     *
     * @param mixed $data 待加密数据（数组/对象转为 JSON）
     * @return string Base64 编码的密文
     */
    public function encrypt(mixed $data): string
    {
        $plaintext = is_string($data) ? $data : (string)json_encode($data, JSON_UNESCAPED_UNICODE);
        $encrypted = openssl_encrypt($plaintext, $this->getCipher(), $this->getKey(), OPENSSL_RAW_DATA, $this->getIv());
        if ($encrypted === false) {
            throw new \RuntimeException('AES 加密失败: ' . openssl_error_string());
        }
        return base64_encode($encrypted);
    }

    /**
     * 解密数据
     *
     * @param string $ciphertext Base64 密文
     * @return mixed 原始数据（若为 JSON 自动还原为关联数组）
     */
    public function decrypt(string $ciphertext): mixed
    {
        $raw = base64_decode($ciphertext, true);
        if ($raw === false) {
            return null;
        }

        $decrypted = openssl_decrypt($raw, $this->getCipher(), $this->getKey(), OPENSSL_RAW_DATA, $this->getIv());
        if ($decrypted === false) {
            return null;
        }

        $json = json_decode($decrypted, true);
        return json_last_error() === JSON_ERROR_NONE ? $json : $decrypted;
    }

    /**
     * 计算签名
     */
    public function sign(string $content, array $options = []): string
    {
        return hash_hmac('sha256', $content, $this->getKey());
    }

    /**
     * 校验请求合法性并解密
     *
     * @param Request $request
     * @return array{0: bool, 1: string, 2: mixed}
     */
    public function verify(Request $request): array
    {
        if (!$this->getConfig('enabled', true)) {
            return [true, '', []];
        }

        // 查找密文来源
        $encrypted = (string)($request->param('_encrypted', '') ?: ($request->post('_encrypted', '') ?: $request->get('_encrypted', '')));
        if ($encrypted === '') {
            $content = trim((string)$request->getContent());
            if ($content !== '') {
                $json = json_decode($content, true);
                $encrypted = $json['_encrypted'] ?? ($json['cipher'] ?? $content);
            }
        }

        if ($encrypted === '') {
            $encrypted = $request->header('x-encrypted-data', '');
        }

        if ($encrypted === '') {
            return [false, '缺少加密请求体参数 (_encrypted)', []];
        }

        // 2. 解密
        $decrypted = $this->decrypt($encrypted);
        if ($decrypted === null) {
            return [false, '请求报文解密失败 (AES Decrypt Failed)', []];
        }

        // 3. 校验时间戳防重放（支持内嵌在解密负载中的 _t / t，或外部 query 上的 t）
        $timestamp = 0;
        if (is_array($decrypted)) {
            $timestamp = (int)($decrypted['_t'] ?? ($decrypted['t'] ?? 0));
        }
        if ($timestamp <= 0) {
            $timestamp = (int)$request->get('t', 0);
        }

        if ($timestamp > 0) {
            [$timeOk, $timeMsg] = $this->checkTimestamp($timestamp);
            if (!$timeOk) {
                return [false, $timeMsg, []];
            }
        }

        return [true, '', $decrypted];
    }

    /**
     * 处理请求并将解密后的参数注入回 Request
     *
     * @param Request $request
     * @return Request
     */
    public function handleRequest(Request $request): Request
    {
        [$valid, $message, $decrypted] = $this->verify($request);
        if (!$valid) {
            throw new \RuntimeException($message ?: 'AES 请求安全校验失败', 401);
        }

        // 若解密出关联数组，将参数无感合并回 Request（包含 route、get、post 与超全局变量）
        if (is_array($decrypted)) {
            $request->setRoute($decrypted);
            $request->withGet(array_merge($request->get(), $decrypted));
            $request->withPost(array_merge($request->post(), $decrypted));
            $_GET = array_merge($_GET, $decrypted);
            $_POST = array_merge($_POST, $decrypted);
            $_REQUEST = array_merge($_REQUEST, $decrypted);
        }

        return $request;

    }
}
