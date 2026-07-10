<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Tests;

use PHPUnit\Framework\TestCase;
use Tavp\Tavpid\Auth\OtpService;

class OtpServiceTest extends TestCase
{
    private OtpService $otp;

    protected function setUp(): void
    {
        $this->otp = new OtpService(ttlMinutes: 5, maxAttempts: 3);
    }

    public function testCreateOtpReturnsCodeAndHash(): void
    {
        $result = $this->otp->createOtp('user@example.com');

        $this->assertArrayHasKey('code', $result);
        $this->assertArrayHasKey('hash', $result);
        $this->assertArrayHasKey('expires_at', $result);
        $this->assertIsArray($result);
        $this->assertSame(6, strlen($result['code']));
        $this->assertMatchesRegularExpression('/^\d{6}$/', $result['code']);
    }

    public function testCreateOtpReturnsConsistentHash(): void
    {
        $result = $this->otp->createOtp('user@example.com');

        $this->assertSame($this->otp->hash($result['code']), $result['hash']);
    }

    public function testVerifyOtpWithValidCode(): void
    {
        $result = $this->otp->createOtp('user@example.com');

        $stored = [
            'hash' => $result['hash'],
            'expires_at' => time() + 300,
            'attempts' => 0,
        ];

        $this->assertTrue($this->otp->verifyOtp($result['code'], $stored));
    }

    public function testVerifyOtpWithInvalidCode(): void
    {
        $result = $this->otp->createOtp('user@example.com');

        $stored = [
            'hash' => $result['hash'],
            'expires_at' => time() + 300,
            'attempts' => 0,
        ];

        $this->assertFalse($this->otp->verifyOtp('000000', $stored));
    }

    public function testVerifyOtpWithExpiredCode(): void
    {
        $result = $this->otp->createOtp('user@example.com');

        $stored = [
            'hash' => $result['hash'],
            'expires_at' => time() - 10,
            'attempts' => 0,
        ];

        $this->assertFalse($this->otp->verifyOtp($result['code'], $stored));
    }

    public function testVerifyOtpWithMaxAttempts(): void
    {
        $result = $this->otp->createOtp('user@example.com');

        $stored = [
            'hash' => $result['hash'],
            'expires_at' => time() + 300,
            'attempts' => 3,
        ];

        $this->assertFalse($this->otp->verifyOtp($result['code'], $stored));
    }

    public function testHashIsConsistent(): void
    {
        $hash1 = $this->otp->hash('123456');
        $hash2 = $this->otp->hash('123456');

        $this->assertSame($hash1, $hash2);
    }

    public function testHashDiffersForDifferentCodes(): void
    {
        $hash1 = $this->otp->hash('123456');
        $hash2 = $this->otp->hash('654321');

        $this->assertNotSame($hash1, $hash2);
    }

    public function testGetMaxAttempts(): void
    {
        $this->assertSame(3, $this->otp->getMaxAttempts());
    }

    public function testGetTtlMinutes(): void
    {
        $this->assertSame(5, $this->otp->getTtlMinutes());
    }
}
