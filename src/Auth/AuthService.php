<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Auth;

/**
 * Orchestrates the OTP-first authentication flow.
 *
 * Passwordless by design: request OTP → verify OTP → logged in.
 * The user store is injected so TAVPid stays storage-agnostic.
 */
class AuthService
{
    public function __construct(
        private OtpService $otpService,
        private UserProvider $users,
    ) {
    }

    /**
     * Create an OTP for the given identifier.
     *
     * @return array{code: string, hash: string, expires_at: int}|null
     */
    public function sendOtp(string $identifier, string $channel = 'email'): ?array
    {
        return $this->otpService->createOtp($identifier, $channel);
    }

    /**
     * Verify a submitted OTP against stored data.
     *
     * @param array{hash: string, expires_at: int, attempts?: int} $stored
     */
    public function verifyOtp(string $code, array $stored): bool
    {
        return $this->otpService->verifyOtp($code, $stored);
    }

    /**
     * Get the OTP service.
     */
    public function otp(): OtpService
    {
        return $this->otpService;
    }

    /**
     * Get the user provider.
     */
    public function users(): UserProvider
    {
        return $this->users;
    }
}
