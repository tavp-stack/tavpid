# tavpid

Module **authentication** untuk TAVP. OTP-first: login bukan cuma pakai
password, tapi bisa lewat berbagai cara.

## Features

- **OTP via Email** — 6-digit code, SHA-256 hashed, 5-min TTL
- **OTP via SMS** — Twilio integration
- **OTP via WhatsApp** — Twilio integration
- **Session auth** — Server-side sessions with device tracking
- **JWT auth** — Access tokens (15 min) + refresh tokens (30 day)
- **Social OAuth** — Google, Apple, GitHub
- **TOTP** — QR code, setup flow, recovery codes
- **Magic Link** — Passwordless email login
- **Role & Permission** — RBAC with middleware guards

## Requirements

- PHP 8.3+
- Phalcon 5.16+
- tavp-core

## Install

```bash
# Via tavp CLI
tavp module:install tavp/tavpid
tavp migrate

# Via Composer
composer require tavp/tavpid
```

## Database tables

| Table | Description |
|---|---|
| `users` | User accounts (id, name, email, phone, email_verified_at) |
| `otp_codes` | OTP codes (id, identifier, code_hash, channel, expires_at, attempts) |
| `user_sessions` | Active sessions (id, user_id, token, device, ip, last_active) |

## Configuration

```php
// config/auth.php
return [
    'otp' => [
        'length' => 6,
        'ttl' => 300,        // 5 minutes
        'max_attempts' => 5,
    ],
    'jwt' => [
        'access_ttl' => 900,     // 15 minutes
        'refresh_ttl' => 2592000, // 30 days
    ],
];
```

## Testing

```bash
composer test
```

## Status

Part of **0.1.0 Genesis** (ZeroVer `0.MINOR.PATCH`). Basic OTP + JWT.
Full features (OAuth, TOTP, RBAC) in `0.2.0` → `0.4.0`.

## License

MIT
