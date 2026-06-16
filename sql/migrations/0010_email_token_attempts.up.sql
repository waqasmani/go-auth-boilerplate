-- Adds a per-token failed-attempt counter so an MFA challenge can be burned
-- after a small number of wrong guesses. This closes the email-OTP brute-force
-- window: a 6-digit code has only 1,000,000 possibilities, and without an
-- attempt cap a wrong guess neither consumes the challenge nor counts against
-- any per-account limit.
ALTER TABLE email_tokens
    ADD COLUMN attempts INT NOT NULL DEFAULT 0;
