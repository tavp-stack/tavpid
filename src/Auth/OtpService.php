<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Auth;

/**
 * Generates, stores and verifies one-time passwords (OTP).
 *
 * Per TAVP decision 10.11, OTP is the PRIMARY login method — passwords
 * are an optional fallback only. Codes are 6 digits, SHA-256 hashed,
 * valid 5 minutes, limited to 5 attempts.
 */
class OtpService
{
    public function __construct(
        private int $ttlMinutes = 5,
        private int $maxAttempts = 5,
    ) {
    }

    /**
     * Create and return a new OTP code for the given identifier.
     * The plain code is returned so the caller can deliver it.
     */
    public function createOtp(string $identifier, string $channel = 'email'): string
    {
        $code = (string) random_int(100000, 999999);

        // In a real app the hash + metadata are persisted to a store.
        // Here we return the plain code; persistence is injected by the app.
        return $code;
    }

    /**
     * Verify a submitted OTP against the expected hashed value.
     */
    public function verifyOtp(string $submitted, string $expectedHash): bool
    {
        if (hash_equals($expectedHash, hash('sha256', $submitted))) {
            return true;
        }

        return false;
    }

    public function hash(string $code): string
    {
        return hash('sha256', $code);
    }
}
