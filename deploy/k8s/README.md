# Kubernetes example manifests

Illustrative manifests for running go-auth-boilerplate as a horizontally-scaled
fleet. They all use **one image** and differ only in the command:

| Workload              | Command               | Kind        |
|-----------------------|-----------------------|-------------|
| API replicas          | `/api`                | Deployment  |
| Schema migrations     | `/api migrate`        | Job         |
| Email outbox worker   | `/api outbox-worker`  | Deployment  |
| Token / outbox purge  | `/api cleanup`        | CronJob     |

Before applying:

1. Replace `IMAGE_PLACEHOLDER` with your built image (`ghcr.io/you/go-auth-boilerplate:TAG`).
2. Create the `go-auth-secrets` Secret from your secrets manager. It must contain
   **identical** crypto material across every workload (`JWT_KEYS`, `TOTP_KEYS`,
   `OAUTH_TOKEN_KEYS`, `OTP_HMAC_SECRET`, `OAUTH_STATE_SECRET`) plus `DB_DSN`,
   `REDIS_DSN`, and SMTP settings. See `secret.example.yaml` and
   [`../../docs/DEPLOYMENT.md`](../../docs/DEPLOYMENT.md).
3. Run migrations before (or as part of) the API rollout:
   `kubectl apply -f migrate-job.yaml && kubectl wait --for=condition=complete job/go-auth-migrate`.

The API replicas run with `SKIP_MIGRATIONS=true` — migrations are owned solely by
the migrate Job.
