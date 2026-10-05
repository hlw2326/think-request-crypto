# hlw2326/request-crypto

[![Latest Stable Version](https://poser.pugx.org/hlw2326/request-crypto/v/stable)](https://packagist.org/packages/hlw2326/request-crypto)
[![Total Downloads](https://poser.pugx.org/hlw2326/request-crypto/downloads)](https://packagist.org/packages/hlw2326/request-crypto)
[![License](https://poser.pugx.org/hlw2326/request-crypto/license)](https://packagist.org/packages/hlw2326/request-crypto)

ThinkPHP / PHP 企业级 HTTP 请求加解密、防篡改签名校验与上下文安全解密扩展包。配套前端 `@hlw-uni-mp/request`。

---

## 🌟 核心特性

- **双向签名防篡改**：采用 SHA256 算法，按业务参数递归 ASCII 字典序排序 + 时间戳 + Nonce + 密钥计算签名，安全防篡改。
- **动态时钟防重放**：毫秒/秒级时间戳比对，内置可配置时钟公差（默认 300 秒），杜绝网络重放攻击。
- **RSA-2048 分段解密**：将客户端敏感设备指纹与用户登录 Token（`x-client-context`）通过 RSA 公钥加密传输，服务端私钥自动分段解密。
- **兼容性卓越**：密文同时支持点分隔 Base64 块（`chunk1.chunk2`）与连续 256 字节原始分块，支持明文 JSON 直通。
- **开箱即用中间件**：提供 `CryptoMiddleware`，支持在全局或特定路由一键校验并注入 `$request->clientContext`。
- **全生态闭环**：与前端 NPM 生态包 `@hlw-uni-mp/request` 100% 协议级对称互通。

---

## 📦 安装说明

通过 Composer 安装：

```bash
composer require hlw2326/request-crypto
```

---

## ⚙️ 配置说明

将 `config/crypto.php` 复制到 ThinkPHP 项目的 `config/crypto.php`：

```php
return [
    // 是否启用加解密与签名验证
    'enabled'     => (bool) (env('CRYPTO_ENABLED', true)),

    // 签名密钥 (用于校验 X-Client-Sign 防篡改)
    'secret'      => (string) (env('CRYPTO_SIGN_SECRET') ?: env('CRYPTO_SECRET', '')),

    // 请求时钟最大容忍偏差秒数 (防重放攻击，默认 300 秒)
    'expire'      => (int) (env('CRYPTO_EXPIRE', 300)),

    // 服务端 RSA-2048 私钥 (用于解密 X-Client-Context 中的设备与 Token)
    'private_key' => (string) env('RSA_PRIVATE_KEY', ''),

    // 服务端 RSA-2048 公钥
    'public_key'  => (string) env('RSA_PUBLIC_KEY', ''),
];
```

或在 `.env` 环境变量中直接指定：

```env
CRYPTO_ENABLED=true
CRYPTO_SIGN_SECRET=your_signature_secret
CRYPTO_EXPIRE=300
RSA_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
RSA_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
```

---

## 🚀 快速上手

### 1. 业务控制器静态调用

```php
use Hlw\Crypto\Crypto;

// 1. 校验当前请求合法性并获取上下文
[$ok, $message, $context] = Crypto::verify($this->request);

if (!$ok) {
    return json(['code' => 0, 'msg' => $message], 401);
}

// 2. 获取客户端解密后的设备信息与登录 Token
$token = (string) ($this->request->header('token', '') ?: ($context['token'] ?? ''));
```

### 2. 使用中间件（一键全局校验）

在 ThinkPHP `app/middleware.php` 或特定应用/路由中注册：

```php
return [
    \Hlw\Crypto\middleware\CryptoMiddleware::class,
];
```

---

## 🤝 配套前端

前端 Uni-app / Vue 项目请配套安装：

```bash
pnpm add @hlw-uni-mp/request
```

---

## 📄 开源协议

本项目基于 [MIT License](LICENSE) 开源。
