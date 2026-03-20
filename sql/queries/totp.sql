-- name: GetUserMFAMethod :one
SELECT mfa_method
FROM users
WHERE id = ?
LIMIT 1;

-- name: GetUserTOTPSecretEncrypted :one
-- Returns NULL when the column is NULL (TOTP not yet set up).
SELECT totp_secret_encrypted
FROM users
WHERE id = ?
LIMIT 1;

-- name: SetUserTOTPSecret :exec
-- Stores the encrypted TOTP secret (pending; not yet active).
UPDATE users
SET totp_secret_encrypted = ?
WHERE id = ?;

-- name: EnableUserTOTP :exec
-- Activates TOTP after the user confirms possession of the secret.
UPDATE users
SET mfa_method       = 'totp',
    two_fa_enabled   = 1,
    totp_enabled_at  = UTC_TIMESTAMP()
WHERE id = ?;

-- name: DisableUserTOTP :exec
-- Reverts the user to email OTP and clears the stored secret.
-- two_fa_enabled is set to 0 so the Login gate (which checks two_fa_enabled)
-- no longer routes this user through the MFA challenge path. Without this,
-- mfa_method and two_fa_enabled would desync: mfa_method='email' but
-- two_fa_enabled=1 causes Login to issue an MFA challenge, InitiateChallenge
-- dispatches to the email-OTP branch, but no OTP token was ever created for
-- this login attempt — producing an infinite challenge loop with no valid
-- redemption path until the challenge token expires (5 minutes).
UPDATE users
SET mfa_method               = 'email',
    two_fa_enabled           = 0,
    totp_secret_encrypted    = NULL,
    totp_enabled_at          = NULL
WHERE id = ?;