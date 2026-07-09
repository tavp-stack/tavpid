<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Auth;

/**
 * Orchestrates the OTP-first authentication flow.
 *
 * Passwordless by design: request OTP → verify OTP → receive tokens.
 * The user store is injected so TAVPid stays storage-agnostic.
 */
class AuthService
{
    public function __construct(
        private OtpService $otpService,
        private TokenService $tokenService,
        private UserProvider $users,
    ) {
    }

    public function sendOtp(string $identifier, string $channel = 'email'): string
    {
        return $this->otpService->createOtp($identifier, $channel);
    }

    public function verifyOtpAndLogin(string $identifier, string $code, string $expectedHash): ?array
    {
        if (!$this->otpService->verifyOtp($code, $expectedHash)) {
            return null;
        }

        $user = $this->users->findByIdentifier($identifier)
            ?? $this->users->create($identifier);

        return $this->tokenService->createTokenPair($user->id);
    }

    public function currentUser(string $accessToken): ?object
    {
        $payload = $this->tokenService->decode($accessToken);
        if ($payload === null || ($payload['type'] ?? '') !== 'access') {
            return null;
        }

        return $this->users->findById($payload['sub']);
    }
}
