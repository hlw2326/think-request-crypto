<?php

declare(strict_types=1);

namespace Hlw\Crypto\driver;

use think\Request;

/**
 * URL 参数字典序 MD5 签名驱动（对齐前端 @hlw-uni/mp-vue 签名规范）
 *
 * @class SigDriver
 * @package Hlw\Crypto\driver
 */
class SigDriver extends AbstractDriver
{
    /**
     * 计算签名
     *
     * @param string $content QUERY_STRING 原始字符串
     * @param array $options 选项（如自定义 reserved 保留排除字段、secret 密钥）
     * @return string MD5 签名
     */
    public function sign(string $content, array $options = []): string
    {
        $secret = (string)($options['secret'] ?? $this->getConfig('secret', ''));
        if ($secret === '') {
            return '';
        }

        $reserved = $options['reserved'] ?? $this->getConfig('reserved', ['sig', 's', '_t']);

        $pairs = array_filter(explode('&', $content), static function (string $pair) use ($reserved): bool {
            if ($pair === '') {
                return false;
            }

            $eqPos = strpos($pair, '=');
            $key = $eqPos === false ? $pair : substr($pair, 0, $eqPos);

            return !in_array($key, $reserved, true);
        });

        sort($pairs, SORT_STRING);
        $signStr = implode('&', $pairs) . '&';

        return md5($signStr . $secret);
    }

    /**
     * 校验请求合法性
     *
     * @param Request $request
     * @return array{0: bool, 1: string, 2: mixed}
     */
    public function verify(Request $request): array
    {
        $secret = (string)$this->getConfig('secret', '');
        // 若未启用或密钥为空则跳过校验
        if ($secret === '' || !$this->getConfig('enabled', true)) {
            return [true, '', []];
        }

        $queryString = (string)$request->server('QUERY_STRING', '');
        if ($queryString === '') {
            $queryString = http_build_query($request->get());
        }
        $expected = $this->sign($queryString);

        if ($expected === '') {
            return [true, '', []];
        }

        $sig = (string)$request->get('sig', '');
        if ($sig === '') {
            return [false, '请求缺少签名参数 (sig)', []];
        }

        if (!hash_equals($expected, $sig)) {
            return [false, '请求签名校验失败 (sig mismatch)', []];
        }

        // 校验时间戳防重放
        $timestamp = (int)$request->get('t', 0);
        [$timeOk, $timeMsg] = $this->checkTimestamp($timestamp);
        if (!$timeOk) {
            return [false, $timeMsg, []];
        }

        return [true, '', []];
    }

    /**
     * 加密数据
     */
    public function encrypt(mixed $data): string
    {
        return is_string($data) ? $this->sign($data) : $this->sign(http_build_query($data));
    }

    /**
     * 解密数据（签名模式下数据为明文）
     */
    public function decrypt(string $ciphertext): mixed
    {
        return $ciphertext;
    }
}
