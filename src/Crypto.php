<?php

declare(strict_types=1);

namespace Hlw\Crypto;

use Hlw\Crypto\contract\CryptoInterface;
use think\Container;
use think\Request;

/**
 * 请求加密与验签门面管理器（对标 think\admin\Storage）
 *
 * @class Crypto
 * @package Hlw\Crypto
 *
 * @method static string encrypt(mixed $data) 加密数据
 * @method static mixed decrypt(string $ciphertext) 解密数据
 * @method static string sign(string $content, array $options = []) 计算签名
 * @method static array verify(Request $request) 校验请求合法性
 * @method static Request handleRequest(Request $request) 校验请求并注入解密参数
 */
abstract class Crypto
{
    /**
     * 驱动单例缓存
     *
     * @var array<string, CryptoInterface>
     */
    protected static array $instances = [];

    /**
     * 获取驱动实例对象
     *
     * @param ?string $driver 驱动名称 (如 sig, aes, hmac, none)
     * @return CryptoInterface
     */
    public static function instance(?string $driver = null): CryptoInterface
    {
        $default = function_exists('config') ? (string)config('crypto.default', 'sig') : (function_exists('env') ? (string)env('CRYPTO_DRIVER', 'sig') : 'sig');
        $driverName = strtolower($driver ?: $default);
        if (isset(static::$instances[$driverName])) {
            return static::$instances[$driverName];
        }

        $class = "Hlw\\Crypto\\driver\\" . ucfirst($driverName) . 'Driver';
        if (!class_exists($class)) {
            throw new \InvalidArgumentException("Crypto driver [{$class}] does not exist.");
        }

        $config = function_exists('config') ? (array)config("crypto.drivers.{$driverName}", []) : [];
        if (class_exists(Container::class) && method_exists(Container::class, 'getInstance')) {
            $instance = Container::getInstance()->make($class, ['config' => $config]);
        } else {
            $instance = new $class($config);
        }

        return static::$instances[$driverName] = $instance;
    }

    /**
     * 静态魔术委托调用当前驱动的方法
     *
     * @param string $method
     * @param array $arguments
     * @return mixed
     */
    public static function __callStatic(string $method, array $arguments)
    {
        return static::instance()->{$method}(...$arguments);
    }
}