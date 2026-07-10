<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Auth;

/**
 * Issues and validates JWT access + refresh tokens.
 *
 * Lightweight implementation — no external dependencies.
 * For production, consider firebase/php-jwt or lcobucci/jwt.
 */
class TokenService
{
    public function __construct(
        private string $secret,
        private int $accessTtlMinutes = 15,
        private int $refreshTtlDays = 30,
    ) {
    }

    /**
     * Create an access + refresh token pair for a user.
     *
     * @return array{access_token: string, refresh_token: string}
     */
    public function createTokenPair(int $userId): array
    {
        $access = $this->encode([
            'sub' => $userId,
            'type' => 'access',
            'iat' => time(),
            'exp' => time() + ($this->accessTtlMinutes * 60),
        ]);

        $refresh = $this->encode([
            'sub' => $userId,
            'type' => 'refresh',
            'iat' => time(),
            'exp' => time() + ($this->refreshTtlDays * 86400),
        ]);

        return ['access_token' => $access, 'refresh_token' => $refresh];
    }

    /**
     * Create a single access token for a user.
     */
    public function createAccessToken(int $userId): string
    {
        return $this->encode([
            'sub' => $userId,
            'type' => 'access',
            'iat' => time(),
            'exp' => time() + ($this->accessTtlMinutes * 60),
        ]);
    }

    /**
     * Decode and validate a token.
     *
     * @return array{sub: int, type: string, iat: int, exp: int}|null
     */
    public function decode(string $token): ?array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            return null;
        }

        [$header, $body, $sig] = $parts;

        // Verify signature.
        $expected = base64_encode(hash_hmac('sha256', "{$header}.{$body}", $this->secret, true));

        if (!hash_equals($expected, $sig)) {
            return null;
        }

        $payload = json_decode(base64_decode($body), true);

        if (!is_array($payload)) {
            return null;
        }

        // Check expiry.
        if (($payload['exp'] ?? 0) < time()) {
            return null;
        }

        return $payload;
    }

    /**
     * Refresh an expired access token using a valid refresh token.
     *
     * @return array{access_token: string, refresh_token: string}|null
     */
    public function refresh(string $refreshToken): ?array
    {
        $payload = $this->decode($refreshToken);

        if ($payload === null || ($payload['type'] ?? '') !== 'refresh') {
            return null;
        }

        return $this->createTokenPair((int) $payload['sub']);
    }

    /**
     * Extract the user ID from a token.
     */
    public function getUserId(string $token): ?int
    {
        $payload = $this->decode($token);

        return $payload !== null ? (int) $payload['sub'] : null;
    }

    /**
     * Check if a token is an access token.
     */
    public function isAccessToken(string $token): bool
    {
        $payload = $this->decode($token);

        return $payload !== null && ($payload['type'] ?? '') === 'access';
    }

    /**
     * Encode a payload into a JWT string.
     */
    private function encode(array $payload): string
    {
        $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $body = base64_encode(json_encode($payload));
        $sig = base64_encode(hash_hmac('sha256', "{$header}.{$body}", $this->secret, true));

        return "{$header}.{$body}.{$sig}";
    }
}
