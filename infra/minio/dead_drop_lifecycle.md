# MinIO Dead-Drop Lifecycle Policy

**Applies to:** `nc-dead-drops` bucket on Node 5
**Decision:** D35 (dead-drops moved from NATS JetStream to MinIO)
**TTL source:** D25 (72-hour default)

---

## Why Dead-Drops Are in MinIO

The original design stored dead-drop mesh messages in NATS JetStream (`MESH` stream, `max_file: 1GB`). At 1,000 active mesh bots this storage fills within hours. NATS is a message bus, not an object store. Multi-hour-TTL objects do not belong in NATS.

MinIO on Node 5 has 10TB NVMe. Dead-drops are stored as objects with a native MinIO lifecycle rule enforcing TTL. The NATS `MESH` stream reverts to a pure live relay (ephemeral, in-flight messages only).

---

## Bucket

```
Bucket name: nc-dead-drops
Node:        Node 5 (co-located with Centaur Failover and main MinIO instance)
Encryption:  AES-256-GCM (same key material as all MinIO objects in this cluster)
Access:      Internal only — not exposed to external clients
```

---

## Object Key Format

```
dead-drop/{recipient_key_id}/{sender_key_id}/{ts_ms}
```

- `recipient_key_id` — lowercase hex Ed25519 public key of the intended recipient (first 16 bytes, 32 hex chars)
- `sender_key_id` — lowercase hex Ed25519 public key of the sender (first 16 bytes, 32 hex chars)
- `ts_ms` — Unix timestamp milliseconds when the message was deposited (i64, decimal string)

**Example:**
```
dead-drop/a3f2c18d9b04e71c/88b42d0cf1ea93a5/1748203847123
```

The key structure enables per-recipient listing without scanning the full bucket:
```
# List all messages waiting for a recipient
mc ls minio/nc-dead-drops/dead-drop/{recipient_key_id}/
```

---

## TTL — 72 Hours

TTL is implemented as a **MinIO lifecycle rule**, not a NATS stream expiry. The rule deletes objects automatically after 72 hours of creation.

```xml
<!-- MinIO lifecycle rule — apply via mc ilm add or MinIO Console -->
<LifecycleConfiguration>
  <Rule>
    <ID>dead-drop-72h-expiry</ID>
    <Status>Enabled</Status>
    <Filter>
      <Prefix>dead-drop/</Prefix>
    </Filter>
    <Expiration>
      <Days>3</Days>
    </Expiration>
  </Rule>
</LifecycleConfiguration>
```

Apply with:
```bash
mc ilm add --expiry-days 3 minio/nc-dead-drops
```

On expiry, MinIO deletes the object silently. The Gateway is responsible for sending an expiry receipt to the sender before deletion (checked at delivery time, not at deletion time — see mesh dead-drop implementation).

---

## Per-Identity Quota

**Maximum objects per recipient: 500**

This quota is enforced at the **Edge Gateway** before the dead-drop write reaches MinIO. The Gateway queries:

```
mc ls minio/nc-dead-drops/dead-drop/{recipient_key_id}/ | wc -l
```

If the count is ≥ 500, the Gateway rejects the send with HTTP 429 (Too Many Requests) and returns an error receipt to the sender. The sender must wait for the recipient to pick up messages before sending more.

The 500-object limit at ~1KB average message size = ~500KB per identity, trivially within storage budget.

---

## Encryption

All objects in `nc-dead-drops` are encrypted with AES-256-GCM before being written to MinIO. Encryption is applied at the application layer (mesh dead-drop writer in `cluster/mesh/src/dead_drop.rs`) using the recipient's X25519-derived key, not MinIO server-side encryption. MinIO server-side encryption is also enabled as a defence-in-depth layer.

The encryption key is derived from the recipient's X25519 mesh key (HD path `m/44'/784'/1'/0'` per D0) using X25519 key agreement. The sender uses their own X25519 private key and the recipient's X25519 public key to derive a shared secret. Only the recipient can decrypt.

---

## Relationship to D25 (Dead-Drop TTL)

D25 specifies a 72-hour TTL for dead-drop messages. That default is unchanged by D35. What changes is the mechanism:

| | **Before D35** | **After D35** |
|---|---|---|
| Storage | NATS JetStream `MESH` stream | MinIO `nc-dead-drops` bucket |
| TTL enforcement | NATS stream `max_age: 72h` | MinIO lifecycle rule (`expiry-days: 3`) |
| Storage limit | 1GB (fills at ~1K bots) | 10TB NVMe (no practical limit) |
| Per-identity quota | None | 500 objects (enforced at Gateway) |
| Encryption | NATS TLS in transit only | AES-256-GCM at rest + TLS in transit |
