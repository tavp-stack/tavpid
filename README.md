# tavpid

Module **authentication** untuk TAVP. OTP-first: login bukan cuma pakai
password, tapi bisa lewat berbagai cara.

## Fitur

- OTP via Email
- OTP via SMS (Twilio) & WhatsApp
- Session auth & JWT auth
- Social OAuth (Google, Apple)
- TOTP / Magic Link
- Role & Permission system

## Cara pakai (rencana)

```
tavp module:install tavp/tavpid
tavp migrate
```

## Status

Planning. Jadi bagian dari milestone `0.2.0` (basic) → `0.4.0` (lengkap).
