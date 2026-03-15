package mailer

import (
	"bytes"
	"fmt"
	"html/template"
)

// verifyEmailTmpl, resetPasswordTmpl, and twoFactorOTPTmpl are parsed once at
// package initialisation. template.Must panics at startup if the template
// source is malformed — the only circumstance under which Execute can fail is
// a broken template, not bad user input.
//
// html/template context-aware auto-escaping handles all XSS vectors:
//
//   - {{.Name}} in a text node → HTML-entity encoded (<, >, &, ", ')
//   - {{.Link}} in an href=""   → URL-sanitised; javascript: URIs are replaced
//     with "#unsafe" so a malformed link can never execute script.
var (
	verifyEmailTmpl   = template.Must(template.New("verify").Parse(verifyEmailHTML))
	resetPasswordTmpl = template.Must(template.New("reset").Parse(resetPasswordHTML))
	twoFactorOTPTmpl  = template.Must(template.New("otp").Parse(twoFactorOTPHTML))
)

// verifyEmailData is the template data bag for [VerifyEmail].
type verifyEmailData struct {
	Name string
	Link string
}

// resetPasswordData is the template data bag for [ResetPassword].
type resetPasswordData struct {
	Name string
	Link string
}

// twoFactorOTPData is the template data bag for [TwoFactorOTP].
type twoFactorOTPData struct {
	Name             string
	Code             string
	SecureAccountURL string
}

// VerifyEmail renders the HTML body for an email-verification message.
// name is the recipient's display name; link is the one-time verification URL.
//
// Both values are HTML- and URL-escaped by html/template, so user-supplied
// names containing angle brackets or script tags are rendered as literal text
// rather than executed as markup.
func VerifyEmail(name, link string) (string, error) {
	var buf bytes.Buffer
	if err := verifyEmailTmpl.Execute(&buf, verifyEmailData{Name: name, Link: link}); err != nil {
		return "", fmt.Errorf("mailer: render verify email: %w", err)
	}
	return buf.String(), nil
}

// ResetPassword renders the HTML body for a password-reset message.
// name is the recipient's display name; link is the one-time reset URL.
func ResetPassword(name, link string) (string, error) {
	var buf bytes.Buffer
	if err := resetPasswordTmpl.Execute(&buf, resetPasswordData{Name: name, Link: link}); err != nil {
		return "", fmt.Errorf("mailer: render reset password: %w", err)
	}
	return buf.String(), nil
}

// TwoFactorOTP renders the HTML body for a 2FA one-time-passcode message.
// name is the recipient's display name; code is the numeric OTP;
// secureAccountURL is the absolute URL the user should visit if they did not
// request this code (e.g. "https://app.example.com/account/security").
// The URL is inserted into an href attribute — html/template will replace any
// javascript: URI with "#unsafe", so a misconfigured value cannot introduce XSS.
func TwoFactorOTP(name, code, secureAccountURL string) (string, error) {
	var buf bytes.Buffer
	if err := twoFactorOTPTmpl.Execute(&buf, twoFactorOTPData{
		Name:             name,
		Code:             code,
		SecureAccountURL: secureAccountURL,
	}); err != nil {
		return "", fmt.Errorf("mailer: render 2fa otp: %w", err)
	}
	return buf.String(), nil
}

// ── Template sources ─────────────────────────────────────────────────────────
//
// These constants hold the raw HTML template sources. They are kept as
// package-level constants (rather than embedded files) so the entire email
// package is a single directory with no extra assets to deploy.
//
// Inline styles are used deliberately: many email clients (Gmail web, Outlook)
// strip <style> blocks, so only inline styles are reliably rendered.

const verifyEmailHTML = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px">
  <tr><td align="center">
    <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e8e8e8;overflow:hidden">
      <!-- Header -->
      <tr><td style="background:#0e0e0e;padding:28px 36px">
        <p style="margin:0;font-size:18px;font-weight:600;color:#ffffff;letter-spacing:0.01em">Verify your email</p>
      </td></tr>
      <!-- Body -->
      <tr><td style="padding:36px">
        <p style="margin:0 0 16px;font-size:15px;color:#3a3a3a;line-height:1.6">Hi {{.Name}},</p>
        <p style="margin:0 0 28px;font-size:15px;color:#5a5a5a;line-height:1.6">
          Thanks for signing up. Click the button below to verify your email address.
          This link expires in <strong>24 hours</strong>.
        </p>
        <table cellpadding="0" cellspacing="0"><tr><td>
          <a href="{{.Link}}" style="display:inline-block;background:#0e0e0e;color:#ffffff;text-decoration:none;padding:13px 28px;border-radius:6px;font-size:14px;font-weight:500;letter-spacing:0.02em">
            Verify Email Address
          </a>
        </td></tr></table>
        <p style="margin:28px 0 0;font-size:13px;color:#9a9a9a;line-height:1.6">
          Or copy this link into your browser:<br>
          <span style="color:#5a5a5a;word-break:break-all">{{.Link}}</span>
        </p>
        <p style="margin:16px 0 0;font-size:13px;color:#9a9a9a">
          If you didn&#39;t create an account, you can safely ignore this email.
        </p>
      </td></tr>
      <!-- Footer -->
      <tr><td style="padding:20px 36px;border-top:1px solid #f0f0f0;background:#fafafa">
        <p style="margin:0;font-size:12px;color:#b0b0b0">Sent by go-auth-boilerplate &nbsp;·&nbsp; Do not reply to this email</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`

const resetPasswordHTML = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px">
  <tr><td align="center">
    <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e8e8e8;overflow:hidden">
      <tr><td style="background:#0e0e0e;padding:28px 36px">
        <p style="margin:0;font-size:18px;font-weight:600;color:#ffffff">Reset your password</p>
      </td></tr>
      <tr><td style="padding:36px">
        <p style="margin:0 0 16px;font-size:15px;color:#3a3a3a;line-height:1.6">Hi {{.Name}},</p>
        <p style="margin:0 0 28px;font-size:15px;color:#5a5a5a;line-height:1.6">
          We received a request to reset your password. Click the button below to choose a new one.
          This link expires in <strong>1 hour</strong>.
        </p>
        <table cellpadding="0" cellspacing="0"><tr><td>
          <a href="{{.Link}}" style="display:inline-block;background:#0e0e0e;color:#ffffff;text-decoration:none;padding:13px 28px;border-radius:6px;font-size:14px;font-weight:500;letter-spacing:0.02em">
            Reset Password
          </a>
        </td></tr></table>
        <p style="margin:28px 0 0;font-size:13px;color:#9a9a9a;line-height:1.6">
          Or copy this link:<br>
          <span style="color:#5a5a5a;word-break:break-all">{{.Link}}</span>
        </p>
        <p style="margin:16px 0 0;font-size:13px;color:#9a9a9a">
          If you didn&#39;t request a password reset, ignore this email — your password won&#39;t change.
        </p>
      </td></tr>
      <tr><td style="padding:20px 36px;border-top:1px solid #f0f0f0;background:#fafafa">
        <p style="margin:0;font-size:12px;color:#b0b0b0">Sent by go-auth-boilerplate &nbsp;·&nbsp; Do not reply to this email</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`

const twoFactorOTPHTML = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px">
  <tr><td align="center">
    <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e8e8e8;overflow:hidden">
      <tr><td style="background:#0e0e0e;padding:28px 36px">
        <p style="margin:0;font-size:18px;font-weight:600;color:#ffffff">Your login code</p>
      </td></tr>
      <tr><td style="padding:36px">
        <p style="margin:0 0 16px;font-size:15px;color:#3a3a3a;line-height:1.6">Hi {{.Name}},</p>
        <p style="margin:0 0 24px;font-size:15px;color:#5a5a5a;line-height:1.6">
          Use the code below to complete your sign-in. It expires in <strong>10 minutes</strong>.
        </p>
        <!-- OTP code block -->
        <table cellpadding="0" cellspacing="0" width="100%"><tr><td align="center" style="padding:20px 0">
          <div style="display:inline-block;background:#f5f5f5;border:1px solid #e0e0e0;border-radius:8px;padding:18px 36px">
            <span style="font-size:36px;font-weight:700;letter-spacing:0.18em;color:#0e0e0e;font-family:'Courier New',monospace">{{.Code}}</span>
          </div>
        </td></tr></table>
        <p style="margin:24px 0 0;font-size:13px;color:#9a9a9a;line-height:1.6">
          Never share this code with anyone. We will never ask you for it.
        </p>
        <p style="margin:10px 0 0;font-size:13px;color:#9a9a9a">
          Didn&#39;t request this? Someone may be trying to access your account —
          <a href="{{.SecureAccountURL}}" style="color:#0e0e0e">secure it now</a>.
        </p>
      </td></tr>
      <tr><td style="padding:20px 36px;border-top:1px solid #f0f0f0;background:#fafafa">
        <p style="margin:0;font-size:12px;color:#b0b0b0">Sent by go-auth-boilerplate &nbsp;·&nbsp; Do not reply to this email</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`
