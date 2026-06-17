# Multi-Instance Deployment Guide

This service is designed to run as **multiple stateless replicas** behind a load
balancer. All shared state lives in **MySQL/MariaDB** (refresh-token families,
email/OAuth tokens, the email outbox) and **Redis** (rate limiting, account
lockout, TOTP-replay prevention, OAuth nonces, access-token revocation). The
application processes themselves hold no durable per-user state, so they scale
horizontally and can be added, removed, or restarted freely.

This guide covers the operational rules that **must** hold across a fleet.

---

## 1. Topology

```
                ┌──────────────┐
   clients ───► │ load balancer│ ──► api replica × N   (SKIP_MIGRATIONS=true)
                └──────────────┘        │   │
                                        │   └────────► Redis (shared)
                                        └────────────► MySQL / MariaDB (shared)

   one-shot / scheduled (NOT in the API pods):
     • migrate          →  `api migrate`        (init-container / Job / CI step)
     • outbox-worker     →  `outbox-worker`      (long-running Deployment, scalable)
     • cleanup           →  `cleanup`            (CronJob)
```

The API replicas, the migrate step, the outbox worker, and the cleanup job all
use the **same image and the same environment** (config is read from env). They
differ only in the command they run and a couple of env toggles.

---

## 2. Environment parity (critical)

Every API replica **must** be given byte-for-byte identical values for all
cryptographic material:

- `JWT_KEYS` — access-token signing/verification key set.
- `TOTP_KEYS`, `OAUTH_TOKEN_KEYS` — secret encryption key sets.
- `OTP_HMAC_SECRET`, `OAUTH_STATE_SECRET`.

If replica A signs an access token with a `kid` that replica B does not have,
B rejects it with `unknown kid` and the user's session breaks on the next
request that happens to hit B. Store these in a secrets manager (Kubernetes
Secret, AWS Secrets Manager, Vault) and mount the **same** secret into every
replica — never generate keys per pod.

The DSNs (`DB_DSN`, `REDIS_DSN`) must point all replicas at the **same** database
and Redis instance/cluster.

---

## 3. Key rotation = ordered rolling deploy

Access-token signing keys rotate with **zero downtime** only if every replica
holds the new key for verification *before* any replica starts signing with it.
Follow the workflow from `.env` exactly, deploying to the **whole fleet** at each
step:

1. Add the new key with `"active": false`. Roll out to all replicas. Now every
   replica can *verify* the new key, though none signs with it yet.
2. Flip the new key to `"active": true` and the old key to `"active": false`.
   Roll out to all replicas. Tokens signed by the old key still verify (the old
   key remains in the set) — no forced re-login.
3. After `JWT_REFRESH_TTL` has elapsed (so no live token was signed by the old
   key), remove the old key entirely. Roll out to all replicas.

Never skip a step or remove the old key early — a replica still signing with a
key another replica has already dropped will break sessions. The same ordered
procedure applies to `TOTP_KEYS` and `OAUTH_TOKEN_KEYS`.

`make gen-secrets` / the `gensecrets` tool produce correctly-shaped rotated key
sets for steps 1–2.

---

## 4. Migrations as a dedicated step

API replicas should run with `SKIP_MIGRATIONS=true`. Apply schema changes with a
**single** migrate run before/alongside the rollout:

```sh
api migrate        # applies all pending migrations, exits 0 on success / 1 on failure
```

Run it as a Kubernetes init-container or a `Job` (see `deploy/k8s/migrate-job.yaml`),
or as a CI/CD stage gated before the new replicas roll. This avoids every replica
contending for golang-migrate's advisory lock on a simultaneous restart or
scale-from-zero, and prevents a slow migration from crash-looping the whole fleet
at the startup watchdog. `api migrate` is idempotent — a second run is a no-op.

> If you leave `SKIP_MIGRATIONS=false`, the app still migrates safely on boot
> (the advisory lock serializes replicas), but you reintroduce the stampede and
> crash-loop risk above. The dedicated step is strongly preferred for a fleet.

---

## 5. Database connection budget

Total server-side connections scale with the fleet:

```
total ≈ (api_replicas × DB_MAX_OPEN_CONNS)
      + (outbox_worker_replicas × DB_MAX_OPEN_CONNS)
      + DB_MAX_OPEN_CONNS   (cleanup, transient)
      + a few                (migrate job, transient)
```

Keep this comfortably under the server's `max_connections`. Example: 10 API
replicas × 25 = 250 connections from the API tier alone. Either raise
`max_connections` or lower `DB_MAX_OPEN_CONNS` when scaling wide. The app logs
the per-replica ceiling at startup (`database pool configured`).

---

## 6. Redis

Redis is a **hard dependency** — rate limiting, lockout, TOTP-replay prevention,
OAuth nonces, and access-token revocation all use it. Run it with persistence
(`appendonly yes`, as in `docker-compose.yml`) so lockout counters and
TOTP-replay markers survive a restart, and use a managed/HA Redis (Sentinel,
Cluster, ElastiCache) in production.

Fail policies by feature (already enforced in code): rate limiting on `/auth/*`
fails **closed**; TOTP-replay fails **closed**; account lockout and access-token
revocation fail **open** (a Redis blip must not lock out or 401 the whole fleet).

---

## 7. Health probes & graceful shutdown

- **Liveness** → `GET /livez` (process-only; never flaps on a transient DB/Redis
  blip).
- **Readiness** → `GET /readyz` (checks DB + Redis; gate load-balancer traffic on
  this).
- On `SIGTERM` the server drains in-flight requests (up to `serverShutdownTimeout`,
  30s) and then drains the mailer. Set the orchestrator's
  `terminationGracePeriodSeconds` to **≥ 35s** so a rolling deploy never kills a
  pod mid-drain. Add a small `preStop` sleep if your LB needs time to deregister
  the endpoint.

The scratch image has no shell; use the binary's own probe in Docker:
`["/api","healthcheck","/readyz"]`.

---

## 8. Background jobs

- **outbox-worker** (`outbox-worker` command) — long-running; drains the
  `email_outbox` table and sends mail. Safe to run **multiple replicas**: it
  claims rows with `FOR UPDATE SKIP LOCKED`, so no email is sent twice. Runs with
  `SKIP_MIGRATIONS=true`.
- **cleanup** (`cleanup` command) — one-shot; run as a CronJob (e.g. hourly) to
  purge expired token rows and old outbox rows. Runs with `SKIP_MIGRATIONS=true`.

Neither runs inside the API pods, so nothing is duplicated per API replica.

---

## 9. Local multi-instance smoke test

`docker-compose.yml` runs a single API instance (fixed host port). To exercise
the fleet locally, layer the scale override (drops the fixed host port and fronts
the replicas with nginx):

```sh
docker compose -f docker-compose.yml -f docker-compose.scale.yml up --build --scale api=3
```

See `docker-compose.scale.yml` for the reverse-proxy front end and the migrate /
outbox-worker one-shots.

---

## 10. Kubernetes

Example manifests live in `deploy/k8s/`:

- `api-deployment.yaml` — `replicas: 3`, `SKIP_MIGRATIONS=true`, `/livez` +
  `/readyz` probes, `terminationGracePeriodSeconds: 40`, secret-backed env.
- `migrate-job.yaml` — `api migrate` as a `Job` (or copy as an init-container).
- `outbox-worker-deployment.yaml` — the mail-sending worker.
- `cleanup-cronjob.yaml` — periodic token/outbox purge.

They are illustrative — wire your own Secret source, image registry, and
resource requests/limits.
