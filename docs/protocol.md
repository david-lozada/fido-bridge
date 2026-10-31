# FIDO Bridge Protocol

Wire format between `fido-bridged` (Fedora) and the Android authenticator app.

## Transport

- **Discovery:** mDNS service `_fidobridge._tcp.local.` advertising the daemon port.
- **Session:** WebSocket over TLS (`wss://`) with mutual certificate authentication.
- **Default port:** `17443`

After pairing, both sides pin the peer certificate fingerprint (SHA-256 of the DER certificate).

## Pairing

1. Daemon runs `fido-bridged pair` and shows a QR code.
2. QR payload (JSON, UTF-8):

```json
{
  "v": 1,
  "host": "192.168.1.10",
  "port": 17443,
  "fp": "<hex SHA-256 of daemon TLS cert>",
  "secret": "<32-byte hex one-time pairing secret>",
  "name": "fedora-desktop"
}
```

3. Phone connects with a freshly generated client certificate and posts:

`POST /pair` with header `X-Pairing-Secret: <secret>` and body:

```json
{
  "name": "Pixel 8",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

4. Daemon verifies the secret (single use, 5-minute TTL), stores the phone cert fingerprint, and returns:

```json
{
  "ok": true,
  "daemon_name": "fedora-desktop",
  "daemon_fp": "<hex>"
}
```

5. Subsequent connections use mTLS: daemon presents its cert; phone presents its cert. Each side rejects unknown fingerprints.

## WebSocket messages

After `GET /ws` upgrades to WebSocket, messages are JSON text frames.

### Common envelope

```json
{
  "type": "<message type>",
  "id": "<uuid>",
  "...": "type-specific fields"
}
```

### Daemon → Phone

#### `ctap_request`

Forwards a raw CTAP2 command (command byte + CBOR) from the browser.

```json
{
  "type": "ctap_request",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "cmd": "<base64 of CTAP2 payload>",
  "timeout_ms": 60000,
  "rp_id": "example.com"
}
```

`rp_id` is best-effort decoded from the CBOR for display; the phone must still parse `cmd` as the source of truth.

#### `ctap_cancel`

```json
{
  "type": "ctap_cancel",
  "id": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### `ping`

```json
{
  "type": "ping",
  "id": "<uuid>",
  "ts": 1730000000
}
```

### Phone → Daemon

#### `ctap_response`

```json
{
  "type": "ctap_response",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "ok",
  "data": "<base64 of CTAP2 response: status byte + CBOR>"
}
```

On failure:

```json
{
  "type": "ctap_response",
  "id": "...",
  "status": "error",
  "error": "user_cancelled",
  "ctap_status": 39
}
```

`ctap_status` is an optional CTAP2 status code (e.g. `0x27` = CTAP2_ERR_OPERATION_DENIED).

#### `pong`

```json
{
  "type": "pong",
  "id": "<uuid>",
  "ts": 1730000000
}
```

#### `hello`

Sent once after WebSocket open:

```json
{
  "type": "hello",
  "id": "<uuid>",
  "name": "Pixel 8",
  "aaguid": "f1d0b71d-0000-4000-8000-0000f1d0b71d",
  "versions": ["FIDO_2_0", "FIDO_2_1_PRE"]
}
```

## Rate limiting

- Max 1 outstanding `ctap_request` per phone connection.
- Max 30 authentication attempts per rolling 5 minutes; excess returns CTAP2_ERR_CHANNEL_BUSY to the browser.
- Pairing secret invalid after first successful use or 5 minutes.

## Cancellation and timeouts

- Browser `CTAPHID_CANCEL` maps to `ctap_cancel`.
- If the phone does not answer within `timeout_ms`, the daemon sends CTAP2_ERR_KEEPALIVE_CANCEL / timeout to the browser and forgets the request id.

## Security requirements

- Private keys never leave the phone Keystore.
- Phone UI must show the relying party ID before biometric confirmation.
- TLS 1.2+ only; cipher suites left to rustls / Android Conscrypt defaults.
- Audit log on the daemon: request id, RP ID, result, timestamp (no credential material).
