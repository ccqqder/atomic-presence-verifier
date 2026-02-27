# Atomic Presence Verifier

Open-source browser-based evidence verifier for [AtomicPresence](https://apps.apple.com/app/atomic-presence/id6740043058) — an iOS app that protects interview integrity through cryptographic hash chains.

## What This Verifies

| Level | Input | Checks |
|-------|-------|--------|
| Level 1 (Session) | `.session.json` | Ed25519 digital signature |
| Level 2 (Audio) | `.m4a` + `.evidence.json` | Ed25519 signature + SHA-256 file checksum |
| Level 3 (Video) | `.mp4` + `.evidence.json` | Ed25519 signature + SHA-256 checksum + QR hash chain |

## Privacy

**All verification runs locally in your browser.** No files or data are uploaded to any server. You can verify this by:

1. Opening browser DevTools > Network tab
2. Running verification — zero network requests are made
3. Reading the [source code](js/verifier.js) (~670 lines)

## Algorithm Specification

### Hash Chain

Each evidence file contains a cryptographic hash chain computed during recording:

```
H_n = SHA-256(H_{n-1} || T_n || salt)
```

- `H_{n-1}`: Previous hash (32 bytes, raw)
- `T_n`: Timestamp in milliseconds since epoch (8 bytes, big-endian Int64)
- `salt`: Random salt (16 bytes, generated at session start)

### QR Payload Format

QR codes embedded in Level 3 video contain:

```
AP|<timestamp_ms>|<hash_prefix_32hex>
```

### Digital Signature

Evidence is signed using **Ed25519** (RFC 8032). The signature covers a pipe-delimited payload of all evidence fields in a deterministic order.

**Level 1 (Session):**
```
sessionId|startTimestamp|endTimestamp|initialHashChainValue|finalHashChainValue|frameCount|salt|deviceId|appVersion|publicKey
```

**Level 2/3 (Evidence):**
```
fileChecksum|startTimestamp|endTimestamp|initialHashChainValue|finalHashChainValue|frameCount|salt|deviceId|appVersion|publicKey
```

### File Integrity

For Level 2 (audio) and Level 3 (video), the SHA-256 checksum of the media file is computed and compared against the signed `fileChecksum` field.

## Dependencies

- [@noble/ed25519](https://github.com/paulmillr/noble-ed25519) v2.1.0 — Ed25519 signature verification (audited, zero-dependency)
- [jsQR](https://github.com/cozmo/jsQR) v1.4.0 — QR code decoder
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) — SHA-256 hashing (built into all modern browsers)

## License

MIT
