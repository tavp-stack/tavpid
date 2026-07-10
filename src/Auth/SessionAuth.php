<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Auth;

/**
 * Session-based authentication for web applications.
 *
 * Wraps AuthService for cookie/session flows. Stores the user ID in
 * PHP's native session. Use for web apps; use TokenService for APIs.
 */
class SessionAuth
{
    public function __construct(
        private AuthService $auth,
        private UserProvider $users,
    ) {
        $this->ensureSession();
    }

    /**
     * Send an OTP to the given email/phone.
     *
     * @return array{hash: string, expires_at: int}|false
     */
    public function requestCode(string $identifier, string $channel = 'email'): array|false
    {
        $otp = $this->auth->sendOtp($identifier, $channel);

        if ($otp === null) {
            return false;
        }

        $_SESSION['tavpid_otp'] = [
            'identifier' => $identifier,
            'hash' => $otp['hash'],
            'expires_at' => $otp['expires_at'],
            'attempts' => 0,
        ];

        return $otp;
    }

    /**
     * Verify the submitted OTP and log the user in.
     */
    public function verify(string $code): bool
    {
        $otp = $_SESSION['tavpid_otp'] ?? null;

        if (!is_array($otp)) {
            return false;
        }

        // Increment attempts.
        $otp['attempts'] = ($otp['attempts'] ?? 0) + 1;
        $_SESSION['tavpid_otp'] = $otp;

        if (!$this->auth->verifyOtpAndLogin($otp['identifier'], $code, $otp)) {
            return false;
        }

        // Find or create user.
        $user = $this->users->findByIdentifier($otp['identifier'])
            ?? $this->users->create($otp['identifier']);

        // Store user in session.
        $_SESSION['tavpid_user_id'] = $user->id ?? $user->getId();
        unset($_SESSION['tavpid_otp']);

        return true;
    }

    /**
     * Check if the user is logged in.
     */
    public function check(): bool
    {
        return !empty($_SESSION['tavpid_user_id']);
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?object
    {
        if (!$this->check()) {
            return null;
        }

        $userId = $_SESSION['tavpid_user_id'];

        return $this->users->findById((int) $userId);
    }

    /**
     * Get the current user's ID.
     */
    public function id(): ?int
    {
        return $this->check() ? (int) $_SESSION['tavpid_user_id'] : null;
    }

    /**
     * Get the pending OTP identifier (email/phone).
     */
    public function pendingIdentifier(): ?string
    {
        return $_SESSION['tavpid_otp']['identifier'] ?? null;
    }

    /**
     * Log the user out.
     */
    public function logout(): void
    {
        unset($_SESSION['tavpid_user_id'], $_SESSION['tavpid_otp']);
    }

    /**
     * Ensure a session is started.
     */
    private function ensureSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }
}
