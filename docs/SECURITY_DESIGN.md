# LabChat security design (planned)

## Goals and limits

- Android phones can chat from different networks through Supabase Realtime/Postgres.
- Supabase stores and relays ciphertext only. It must never receive a message key or plaintext.
- No email/password/account experience. Supabase Anonymous Auth can provide a per-installation `auth.uid()` for database access without a user-facing login.
- No claim of Signal-level protection until the protocol, recovery, metadata, key changes, and two-device behavior have been reviewed and exercised.

## Key lifecycle

1. On first launch, create a device identity with a reviewed protocol/library. Keep private material in Android Keystore-backed encrypted storage, never preferences, logs, backups, or Supabase.
2. Publish only a public identity key. Pairing uses a short-lived, single-use text invite that binds the host public key. Users must compare and verify both device fingerprints out of band; otherwise a malicious relay can substitute keys. QR scanning is not implemented yet.
3. Establish a distinct per-conversation secret with X25519 and HKDF-SHA-256, binding protocol version, conversation ID, and both key identities as context. Do not use the raw X25519 result directly as an encryption key.
4. Encrypt each message on the sender with authenticated encryption (AES-256-GCM or ChaCha20-Poly1305). Use a fresh, unique nonce for every encryption under a key and authenticate the conversation ID, sender ID, and protocol version as associated data. Store ciphertext, nonce, tag, sender ID, and timestamp only.
5. Decrypt only on the recipient device. Reject invalid authentication tags and unknown protocol versions. Never silently fall back to plaintext.

## Important v1 limitation

A static X25519 shared key plus per-message random nonces does **not** provide forward secrecy or post-compromise recovery. A later version should adopt a well-reviewed asynchronous ratchet (for example, the Signal protocol) rather than inventing one. Until then, keep the prototype status explicit and do not describe it as production-secure.

## Server and operational protections

- Use anonymous Auth for RLS identity; it is not a proof of a person's real-world identity.
- RLS must restrict conversation/message reads to current members, and writes to the authenticated sender. Pairing RPCs must be narrowly scoped, one-time, expiring, and enforce a two-member limit.
- A public Supabase key is expected in the app. A service-role key is never safe in a mobile binary.
- The server still sees message timing, sender/device IDs, conversation membership, and approximate traffic volume. E2EE does not hide metadata.
- Supabase Realtime is a transport for encrypted records, not the source of cryptographic trust.
- Android backup/restore, app reinstall, key loss, device change, screenshots, notifications, and lock-screen previews need explicit product decisions before release.

## Current implementation status

- Supabase client initialization and an anonymous session are wired. Session tokens and X25519 identity seeds use the platform secure-storage plugin. Android app backup is disabled so a restored encrypted preferences file cannot be paired with a missing Android Keystore key.
- Device identity generation, SHA-256 fingerprints, X25519 + HKDF-SHA-256 conversation-key derivation, and AES-256-GCM message envelopes are implemented as isolated Dart services. Pairing RPC calls, peer-key verification storage, and a ciphertext-only message repository are also present.
- The UI now supports a copy/paste invite, host/guest fingerprint comparison, storing verified peer keys, and a live ciphertext-only text-message path for paired chats. The inbox sample rows remain local previews. QR scanning and a list of previously paired conversations are not implemented.
- Hosted RLS, RPC, Realtime, anonymous-auth, and two-device delivery behavior have not been independently verified from this workspace. A successful local analyzer run does not establish that production backend configuration is correct.
- V1's static X25519 key agreement does not provide forward secrecy. The code must remain experimental until a ratcheting protocol is adopted and the full pairing/message flow is reviewed and verified on two Android devices.
- Migration `202610160002_pairing_rpcs.sql` adds the one-use invite RPCs, message version field, and Realtime publication membership. Both migrations require a real-project RLS and end-to-end verification.
