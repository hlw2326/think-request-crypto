<?php

declare(strict_types=1);

namespace Hlw\Crypto\driver;

use think\Request;

/**
 * 字典签名驱动
 *
 * @class SignDriver
 * @package Hlw\Crypto\driver
 */
class SignDriver extends AbstractDriver
{
    /**
     * 计算签名值
     *
     * @param string $content 查询原始字串
     * @param array $options 签名附加选项
     * @return string MD5 签名文本
     */
    public function sign(string $content, array $options = []): string
    {
        $secret = (string) ($options['secret'] ?? $this->getConfig('secret', ''));
        if ($secret === '') {
            return '';
        }

        $reserved = $options['reserved'] ?? $this->getConfig('reserved', ['sign', 'sig', 's', '_t']);

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
     * 校验合法性
     *
     * @param Request $request 请求实例项
     * @return array{0: bool, 1: string, 2: mixed} 校验结果组
     */
    public function verify(Request $request): array
    {
        $secret = (string) $this->getConfig('secret', '');
        if ($secret === '' || !$this->getConfig('enabled', true)) {
            return [true, '', []];
        }

        $queryString = (string) $request->server('QUERY_STRING', '');
        if ($queryString === '') {
            $queryString = http_build_query($request->get());
        }
        $expected = $this->sign($queryString);

        if ($expected === '') {
            return [true, '', []];
        }

        $clientSign = (string) ($request->get('sign', '') ?: $request->get('sig', ''));
        if ($clientSign === '') {
            return [false, '请求缺少签名参数', []];
        }

        if (!hash_equals($expected, $clientSign)) {
            return [false, '请求签名校验失败', []];
        }

        // 校验时间戳防重放
        $timestamp = (int) ($request->get('_t', 0) ?: $request->get('t', 0));
        if ($timestamp > 0) {
            [$isTimeOk, $timeMsg] = $this->checkTimestamp($timestamp);
            if (!$isTimeOk) {
                return [false, $timeMsg, []];
            }
        }

        return [true, '', []];
    }

    /**
     * 加密数据体
     *
     * @param mixed $data 待加密数据
     * @return string
     */
    public function encrypt(mixed $data): string
    {
        return is_string($data) ? $this->sign($data) : $this->sign(http_build_query($data));
    }

    /**
     * 解密数据体
     *
     * @param string $ciphertext 密文字符串
     * @return mixed
     */
    public function decrypt(string $ciphertext): mixed
    {
        return $ciphertext;
    }
}
