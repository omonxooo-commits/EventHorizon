# Automated Secret Rotation Policy

## Overview

EventHorizon supports automated rotation of provider credentials (API keys and tokens). Each credential can have a rotation policy that defines how often its secrets should be replaced and whether rotation should happen automatically.

## How It Works

1. A **RotationPolicy** is attached to a `Credential` document.
2. The policy defines an `intervalDays` (1–365) and an `autoRotate` flag.
3. When rotation is triggered (manually or automatically), the service:
   - Generates new cryptographically-secure random tokens.
   - Encrypts them with AES-256-GCM before storing.
   - Updates the credential in the database.
   - Writes an immutable audit log entry.
   - Updates `lastRotatedAt` and `nextRotationAt` on the policy.

## API Endpoints

All endpoints require a valid `Authorization: Bearer <token>` header.

### Rotation Policy CRUD

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/credentials/:credentialId/rotation-policy` | Get the rotation policy |
| `POST` | `/api/credentials/:credentialId/rotation-policy` | Create a rotation policy |
| `PUT` | `/api/credentials/:credentialId/rotation-policy` | Update a rotation policy |
| `DELETE` | `/api/credentials/:credentialId/rotation-policy` | Delete a rotation policy |

#### Create / Update Policy Body

```json
{
  "intervalDays": 30,
  "autoRotate": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `intervalDays` | integer | Yes (create) | Days between rotations (1–365) |
| `autoRotate` | boolean | No | Enable automatic rotation (default: `false`) |
| `status` | string | No (update only) | `active` or `paused` |

### Manual Rotation

```
POST /api/credentials/:credentialId/rotate
```

Immediately rotates the credential's secrets. Returns the new plain-text tokens — **store them securely, they are not retrievable again**.

**Response:**
```json
{
  "success": true,
  "data": {
    "credentialId": "...",
    "provider": "slack",
    "newAccessToken": "...",
    "newRefreshToken": "...",
    "rotatedAt": "2026-05-01T22:00:00.000Z"
  }
}
```

### Trigger Due Auto-Rotations (Admin)

```
POST /api/credentials/rotate/run-due
```

Requires the `manage_credentials` permission. Processes all policies where `autoRotate=true`, `status=active`, and `nextRotationAt <= now`.

## Rotation Policy Model

```
RotationPolicy {
  credentialId   ObjectId  (ref: Credential)
  userId         ObjectId  (ref: User)
  intervalDays   Number    (1–365)
  autoRotate     Boolean
  lastRotatedAt  Date
  nextRotationAt Date      (auto-computed: lastRotatedAt + intervalDays)
  rotationCount  Number
  status         String    (active | paused)
}
```

## Audit Logging

Every rotation event is recorded in the `audit_logs` collection with:

- `operation: "UPDATE"`
- `resourceType: "Credential"`
- `resourceId`: the credential's `_id`
- `organization`: the user's organization
- `userId`: who triggered the rotation
- `ipAddress` / `userAgent`: request metadata
- `changes.diff`: records that `accessToken` was rotated (values are redacted)

Audit logs are immutable and integrity-verified via SHA-256 hash.

## Scheduling Auto-Rotation

To run auto-rotation on a schedule, call the `run-due` endpoint from a cron job or use the `runDueRotations()` service function directly:

```js
const { runDueRotations } = require('./src/services/rotation.service');

// e.g. every hour
setInterval(runDueRotations, 60 * 60 * 1000);
```

## Security Notes

- New tokens are generated using `crypto.randomBytes(48)` (384 bits of entropy).
- Tokens are encrypted at rest with AES-256-GCM before being stored.
- The plain-text token is returned **only once** at rotation time.
- Rotation audit logs cannot be modified or deleted.
- The `run-due` endpoint requires the `manage_credentials` permission.
