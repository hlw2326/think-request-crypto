# hlw2326/request-crypto

[![Latest Stable Version](https://poser.pugx.org/hlw2326/request-crypto/v/stable)](https://packagist.org/packages/hlw2326/request-crypto)
[![Total Downloads](https://poser.pugx.org/hlw2326/request-crypto/downloads)](https://packagist.org/packages/hlw2326/request-crypto)
[![License](https://poser.pugx.org/hlw2326/request-crypto/license)](https://packagist.org/packages/hlw2326/request-crypto)

ThinkPHP / PHP 企业级多驱动 HTTP 请求加解密、防篡改签名与时钟防重放验证扩展库（对标 `think\admin\Storage` 驱动化架构设计）。

---

## 🌟 特性亮点

- **对标 `Storage` 门面设计**：支持通过 `Crypto::verify($request)`、`Crypto::encrypt($data)`、`Crypto::decrypt($cipher)` 统一静态门面调用，支持根据需求动态切换驱动实例 `Crypto::instance('aes')`。
- **四大驱动体系**：
  1. `sig`：**URL 参数字典排序 + MD5 验签**，支持 5 分钟动态时钟防重放，完美对齐前端 `@hlw-vue/request-crypto` 与 `@hlw-uni/mp-vue`。
  2. `aes`：**全报文对称加密 (AES-128/256-CBC)**，客户端上送 JSON 密文，中间件/服务端验证通过后**自动回写注入至 `$request` 与 `$_POST`**，业务控制器无感读取参数。
  3. `hmac`：**工业级 HMAC-SHA256 标头验签**，通过 HTTP Headers (`X-Signature`, `X-Timestamp`, `X-Nonce`) 认证请求。
  4. `none`：**免密直通空驱动**，用于本地研发、PHPUnit 单测与 Postman/Apifox 接口无加密调试。
- **环境无缝解耦**：可在 `.env` 中通过 `CRYPTO_DRIVER=sig` / `CRYPTO_DRIVER=aes` 随时无感切换，代码零改造。
- **开箱即用中间件**：内置 `CryptoMiddleware`，可在全局或路由中一键挂载。
- **跨语言/跨平台对齐**：前端对应独立 NPM 包 `@hlw-vue/request-crypto`，跨端加解密 100% 互通。

---

## 📦 安装说明

通过 Composer 安装：

```bash
composer require hlw2326/request-crypto
```

---

## ⚙️ 配置说明

在项目 `config/crypto.php`（或 ThinkPHP 配置目录）中配置：

```php
return [
    // 默认驱动：sig | aes | hmac | none
    'default' => env('CRYPTO_DRIVER', 'sig'),

    // 驱动配置
    'drivers' => [
        'sig' => [
            'secret' => env('CRYPTO_SIG_SECRET', 'hlw2326'),
            'expire' => env('CRYPTO_EXPIRE', 300), // 签名有效期(秒)
        ],
        'aes' => [
            'key'    => env('CRYPTO_AES_KEY', 'hlw2326key123456'), // 16或32位
            'iv'     => env('CRYPTO_AES_IV', 'hlw2326iv1234567'),  // 16位
            'method' => 'AES-128-CBC',
            'expire' => env('CRYPTO_EXPIRE', 300),
        ],
        'hmac' => [
            'secret' => env('CRYPTO_HMAC_SECRET', 'hlw2326'),
            'algo'   => 'sha256',
            'expire' => env('CRYPTO_EXPIRE', 300),
        ],
        'none' => [],
    ],
];
```

在 `.env` 中指定默认驱动：

```env
CRYPTO_DRIVER=sig
CRYPTO_SIG_SECRET=hlw2326
CRYPTO_AES_KEY=hlw2326key123456
CRYPTO_AES_IV=hlw2326iv1234567
CRYPTO_EXPIRE=300
```

---

## 🚀 快速上手

### 1. 验证请求签名或解密

```php
use Hlw\Crypto\Crypto;

// 校验当前请求
[$ok, $message, $data] = Crypto::verify($request);

if (!$ok) {
    // 验签失败或请求重放
    return json(['code' => 0, 'info' => $message], 401);
}

// 验签成功，$data 为解析出的有效请求载荷
```

### 2. 使用中间件（推荐）

在 ThinkPHP `app/middleware.php` 或特定路由中注册：

```php
return [
    \Hlw\Crypto\middleware\CryptoMiddleware::class,
];
```

开启中间件后：
- `sig` / `hmac` 模式下非法请求会被自动拦截，返回 401 JSON；
- `aes` 模式下加密请求会被自动解密，解密后的参数自动注入 `$request`，在控制器中直接使用 `$request->param()` 即可！

### 3. 数据加解密

```php
use Hlw\Crypto\Crypto;

// 加密数据（采用当前驱动或指定驱动）
$ciphertext = Crypto::encrypt(['order_id' => '10086', 'amount' => 99.9]);

// 解密数据
$payload = Crypto::decrypt($ciphertext);

// 手动指定使用 AES 驱动
$aesPayload = Crypto::instance('aes')->decrypt($ciphertext);
```

---

## 🤝 搭配前端

前端 UniApp / Vue 3 项目请配套安装：

```bash
pnpm add @hlw-vue/request-crypto
```

前端统一在 `.env` 中设置驱动名称与密钥，即可实现全自动跨端签名/报文加解密。

---

## 📄 开源协议

本项目基于 [MIT License](LICENSE) 开源。
