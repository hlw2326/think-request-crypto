<?php

declare(strict_types=1);

namespace Hlw\Crypto\contract;

use think\Request;

/**
 * 请求加密与验签驱动契约接口
 *
 * @interface CryptoInterface
 * @package Hlw\Crypto\contract
 */
interface CryptoInterface
{
    /**
     * 加密数据
     *
     * @param mixed $data 待加密数据（标量或数组）
     * @return string 加密后的密文字符串
     */
    public function encrypt(mixed $data): string;

    /**
     * 解密数据
     *
     * @param string $ciphertext 密文字符串
     * @return mixed 解密后的原始数据
     */
    public function decrypt(string $ciphertext): mixed;

    /**
     * 计算签名
     *
     * @param string $content 签名原文字符串
     * @param array $options 附加参数
     * @return string 签名值
     */
    public function sign(string $content, array $options = []): string;

    /**
     * 校验请求合法性（验签/防重放/解密检查）
     *
     * @param Request $request ThinkPHP Request 实例
     * @return array{0: bool, 1: string, 2: mixed} [是否通过, 错误提示, 解密数据/负载]
     */
    public function verify(Request $request): array;

    /**
     * 处理请求（自动校验并将解密后的数据注入回 Request）
     *
     * @param Request $request
     * @return Request 处理后的 Request 对象
     * @throws \RuntimeException 当校验失败时抛出异常
     */
    public function handleRequest(Request $request): Request;
}
