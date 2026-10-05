<?php

declare(strict_types=1);

/**
 * HTTP 请求加解密与签名配置
 */
return [
    // 是否启用加解密与签名验证
    'enabled'     => (bool) (env('CRYPTO_ENABLED', true)),

    // 签名密钥 (用于校验 X-Client-Sign 防篡改)
    'secret'      => (string) (env('CRYPTO_SIGN_SECRET') ?: env('CRYPTO_SECRET', '')),

    // 请求时钟最大容忍偏差秒数 (防重放攻击，默认 300 秒)
    'expire'      => (int) (env('CRYPTO_EXPIRE', 300)),

    // 服务端 RSA-2048 私钥 (用于解密 X-Client-Context 中的设备与 Token)
    'private_key' => (string) env('RSA_PRIVATE_KEY', ''),

    // 服务端 RSA-2048 公钥 (用于加密数据)
    'public_key'  => (string) env('RSA_PUBLIC_KEY', ''),
];
