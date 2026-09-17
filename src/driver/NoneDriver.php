<?php

declare(strict_types=1);

namespace Hlw\Crypto\driver;

use think\Request;

/**
 * 空驱动（直通放行，用于本地开发、免加密环境与单测）
 *
 * @class NoneDriver
 * @package Hlw\Crypto\driver
 */
class NoneDriver extends AbstractDriver
{
    public function encrypt(mixed $data): string
    {
        return is_string($data) ? $data : (string)json_encode($data, JSON_UNESCAPED_UNICODE);
    }

    public function decrypt(string $ciphertext): mixed
    {
        $json = json_decode($ciphertext, true);
        return json_last_error() === JSON_ERROR_NONE ? $json : $ciphertext;
    }

    public function sign(string $content, array $options = []): string
    {
        return '';
    }

    public function verify(Request $request): array
    {
        return [true, '', []];
    }
}
