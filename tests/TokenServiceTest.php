<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Tests;

use PHPUnit\Framework\TestCase;
use Tavp\Tavpid\Auth\TokenService;

class TokenServiceTest extends TestCase
{
    private TokenService $token;

    protected function setUp(): void
    {
        $this->token = new TokenService(
            secret: 'test-secret-key-12345',
            accessTtlMinutes: 15,
            refreshTtlDays: 30,
        );
    }

    public function testCreateTokenPairReturnsTwoTokens(): void
    {
        $tokens = $this->token->createTokenPair(1);

        $this->assertArrayHasKey('access_token', $tokens);
        $this->assertArrayHasKey('refresh_token', $tokens);
        $this->assertNotEmpty($tokens['access_token']);
        $this->assertNotEmpty($tokens['refresh_token']);
    }

    public function testDecodeValidAccessToken(): void
    {
        $tokens = $this->token->createTokenPair(42);
        $payload = $this->token->decode($tokens['access_token']);

        $this->assertNotNull($payload);
        $this->assertSame(42, $payload['sub']);
        $this->assertSame('access', $payload['type']);
    }

    public function testDecodeValidRefreshToken(): void
    {
        $tokens = $this->token->createTokenPair(42);
        $payload = $this->token->decode($tokens['refresh_token']);

        $this->assertNotNull($payload);
        $this->assertSame(42, $payload['sub']);
        $this->assertSame('refresh', $payload['type']);
    }

    public function testDecodeInvalidToken(): void
    {
        $payload = $this->token->decode('invalid.token.here');

        $this->assertNull($payload);
    }

    public function testDecodeTamperedToken(): void
    {
        $tokens = $this->token->createTokenPair(1);
        $parts = explode('.', $tokens['access_token']);
        $parts[2] = base64_encode('tampered');
        $tampered = implode('.', $parts);

        $this->assertNull($this->token->decode($tampered));
    }

    public function testGetUserId(): void
    {
        $tokens = $this->token->createTokenPair(99);

        $this->assertSame(99, $this->token->getUserId($tokens['access_token']));
    }

    public function testIsAccessToken(): void
    {
        $tokens = $this->token->createTokenPair(1);

        $this->assertTrue($this->token->isAccessToken($tokens['access_token']));
        $this->assertFalse($this->token->isAccessToken($tokens['refresh_token']));
    }

    public function testRefreshTokens(): void
    {
        $tokens = $this->token->createTokenPair(1);

        // Decode the original refresh token.
        $originalPayload = $this->token->decode($tokens['refresh_token']);
        $this->assertNotNull($originalPayload);

        // Refresh should return new tokens.
        $newTokens = $this->token->refresh($tokens['refresh_token']);
        $this->assertNotNull($newTokens);

        // New access token should decode to same user.
        $newPayload = $this->token->decode($newTokens['access_token']);
        $this->assertNotNull($newPayload);
        $this->assertSame(1, $newPayload['sub']);
        $this->assertSame('access', $newPayload['type']);
    }

    public function testRefreshWithAccessTokenFails(): void
    {
        $tokens = $this->token->createTokenPair(1);
        $result = $this->token->refresh($tokens['access_token']);

        $this->assertNull($result);
    }

    public function testCreateAccessToken(): void
    {
        $token = $this->token->createAccessToken(5);
        $payload = $this->token->decode($token);

        $this->assertNotNull($payload);
        $this->assertSame(5, $payload['sub']);
        $this->assertSame('access', $payload['type']);
    }
}
