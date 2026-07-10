<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Auth;

/**
 * Generates, stores and verifies one-time passwords (OTP).
 *
 * Per TAVP decision 10.11, OTP is the PRIMARY login method — passwords
 * are an optional fallback only. Codes are 6 digits, SHA-256 hashed,
 * valid 5 minutes, limited to 5 attempts.
 *
 * This service is stateless — persistence is handled by the caller.
 * The caller stores the hash + metadata and passes it back for verification.
 */
class OtpService
{
    public function __construct(
        private int $ttlMinutes = 5,
        private int $maxAttempts = 5,
        private int $codeLength = 6,
    ) {
    }

    /**
     * Create a new OTP code for the given identifier.
     *
     * Returns the plain code (to be sent via email/SMS) and the hash
     * (to be stored by the caller for verification).
     *
     * @return array{code: string, hash: string, expires_at: int}
     */
    public function createOtp(string $identifier, string $channel = 'email'): array
    {
        $code = $this->generateCode();
        $hash = $this->hash($code);
        $expiresAt = time() + ($this->ttlMinutes * 60);

        return [
            'code' => $code,
            'hash' => $hash,
            'expires_at' => $expiresAt,
        ];
    }

    /**
     * Verify a submitted OTP against the expected hash.
     *
     * @param array{hash: string, expires_at: int, attempts?: int} $stored
     */
    public function verifyOtp(string $submitted, array $stored): bool
    {
        // Check expiry.
        if (($stored['expires_at'] ?? 0) < time()) {
            return false;
        }

        // Check attempt limit.
        $attempts = $stored['attempts'] ?? 0;
        if ($attempts >= $this->maxAttempts) {
            return false;
        }

        // Check code.
        return hash_equals($stored['hash'] ?? '', $this->hash($submitted));
    }

    /**
     * Hash an OTP code for storage/comparison.
     */
    public function hash(string $code): string
    {
        return hash('sha256', $code);
    }

    /**
     * Get the maximum number of verification attempts.
     */
    public function getMaxAttempts(): int
    {
        return $this->maxAttempts;
    }

    /**
     * Get the TTL in minutes.
     */
    public function getTtlMinutes(): int
    {
        return $this->ttlMinutes;
    }

    /**
     * Generate a numeric OTP code.
     */
    private function generateCode(): string
    {
        $min = (int) str_repeat('1', $this->codeLength);
        $max = (int) str_repeat('9', $this->codeLength);

        return (string) random_int($min, $max);
    }
}
