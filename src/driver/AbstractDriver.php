<?php

declare(strict_types=1);

namespace Hlw\Crypto\driver;

use Hlw\Crypto\contract\CryptoInterface;
use think\Request;

/**
 * 驱动抽象基类
 *
 * @class AbstractDriver
 * @package Hlw\Crypto\driver
 */
abstract class AbstractDriver implements CryptoInterface
{
    /**
     * 驱动配置
     *
     * @var array
     */
    protected array $config = [];

    /**
     * 构造函数
     *
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->initialize();
    }

    /**
     * 初始化钩子
     */
    protected function initialize(): void
    {
    }

    /**
     * 获取驱动配置项
     *
     * @param ?string $key 配置键
     * @param mixed $default 默认值
     * @return mixed
     */
    public function getConfig(?string $key = null, mixed $default = null): mixed
    {
        if (is_null($key)) {
            return $this->config;
        }
        return $this->config[$key] ?? $default;
    }

    /**
     * 时间戳防重放校验
     *
     * @param int $timestamp 客户端传入时间戳（秒）
     * @param ?int $maxSkew 允许的最大时钟偏差（秒），默认读取配置 expire 或 300
     * @return array{0: bool, 1: string}
     */
    public function checkTimestamp(int $timestamp, ?int $maxSkew = null): array
    {
        if ($timestamp <= 0) {
            return [false, '请求缺少有效时间戳'];
        }

        $maxSkew = $maxSkew ?? (int)$this->getConfig('expire', 300);
        if ($maxSkew > 0 && abs(time() - $timestamp) > $maxSkew) {
            return [false, '请求链接已过期或时间偏差过大'];
        }

        return [true, ''];
    }

    /**
     * 默认处理请求：验签失败抛出异常，成功返回 Request
     *
     * @param Request $request
     * @return Request
     * @throws \RuntimeException
     */
    public function handleRequest(Request $request): Request
    {
        [$valid, $message, $data] = $this->verify($request);
        if (!$valid) {
            throw new \RuntimeException($message ?: '请求安全校验失败', 401);
        }
        return $request;
    }
}
