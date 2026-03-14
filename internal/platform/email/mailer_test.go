package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/smtp"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── Test fixtures ─────────────────────────────────────────────────────────────

var (
	testCfg = Config{
		Host: "smtp.example.com",
		Port: 587,
		From: "Sender <from@example.com>",
	}
	testMsg = Message{
		To:      "to@example.com",
		Subject: "Hello",
		Text:    "Plain text body.",
	}
)

// newTestMailer creates a Mailer wired with client as the dial result.
// retryBase is zeroed so retry loops are instant. Shutdown is registered as a
// test cleanup.
func newTestMailer(t *testing.T, cfg Config, client smtpClient) *Mailer {
	t.Helper()
	m, err := New(cfg, WithWorkers(1), WithQueueSize(16))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.retryBase = 0
	if client != nil {
		m.dialSMTP = func(_ context.Context, _ string, _ *tls.Config) (smtpClient, error) {
			return client, nil
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		m.Shutdown(ctx) //nolint:errcheck
	})
	return m
}

// ── Mock types ────────────────────────────────────────────────────────────────

// mockWriteCloser is an in-memory io.WriteCloser with injectable errors.
type mockWriteCloser struct {
	buf      strings.Builder
	writeErr error
	closeErr error
}

func (m *mockWriteCloser) Write(p []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.buf.Write(p)
}

func (m *mockWriteCloser) Close() error { return m.closeErr }

// mockSMTPClient implements smtpClient for testing. The zero value succeeds
// on every call (no STARTTLS extension, no authentication required).
type mockSMTPClient struct {
	hasSTARTTLS bool // whether Extension("STARTTLS") returns true
	startTLSErr error
	authErr     error
	mailFromErr error
	rcptErr     error
	dataErr     error
	wc          *mockWriteCloser // nil → auto-created on first Data() call
	quitErr     error

	mu         sync.Mutex
	authCalled bool
	quitCalled bool
	mailFrom   string
	rcptTo     string
}

func (c *mockSMTPClient) Extension(name string) (bool, string) {
	if strings.EqualFold(name, "STARTTLS") {
		return c.hasSTARTTLS, ""
	}
	return false, ""
}

func (c *mockSMTPClient) StartTLS(cfg *tls.Config) error { return c.startTLSErr }

func (c *mockSMTPClient) Auth(_ smtp.Auth) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authCalled = true
	return c.authErr
}

func (c *mockSMTPClient) Mail(from string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mailFrom = from
	return c.mailFromErr
}

func (c *mockSMTPClient) Rcpt(to string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rcptTo = to
	return c.rcptErr
}

func (c *mockSMTPClient) Data() (io.WriteCloser, error) {
	if c.dataErr != nil {
		return nil, c.dataErr
	}
	if c.wc == nil {
		c.wc = &mockWriteCloser{}
	}
	return c.wc, nil
}

func (c *mockSMTPClient) Quit() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.quitCalled = true
	return c.quitErr
}

func (c *mockSMTPClient) Close() error { return nil }

// ── Error type ────────────────────────────────────────────────────────────────

func TestError_MessageWithCode(t *testing.T) {
	e := &Error{Op: "auth", Err: errors.New("bad creds"), Code: 535}
	want := "mailer: auth (smtp 535): bad creds"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestError_MessageWithoutCode(t *testing.T) {
	e := &Error{Op: "dial", Err: errors.New("refused")}
	want := "mailer: dial: refused"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	e := &Error{Op: "send", Err: inner}
	if !errors.Is(e, inner) {
		t.Error("errors.Is through Unwrap should find inner error")
	}
}

func TestError_IsRetryable(t *testing.T) {
	tests := []struct {
		name string
		e    *Error
		want bool
	}{
		{"context.Canceled", &Error{Err: context.Canceled}, false},
		{"context.DeadlineExceeded", &Error{Err: context.DeadlineExceeded}, false},
		{"smtp 421 temporary", &Error{Code: 421, Err: errors.New("x")}, true},
		{"smtp 450 temporary", &Error{Code: 450, Err: errors.New("x")}, true},
		{"smtp 499 boundary", &Error{Code: 499, Err: errors.New("x")}, true},
		{"smtp 500 permanent", &Error{Code: 500, Err: errors.New("x")}, false},
		{"smtp 550 permanent", &Error{Code: 550, Err: errors.New("x")}, false},
		{"no code defaults retryable", &Error{Err: errors.New("network hiccup")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.IsRetryable(); got != tt.want {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ── mailerErr ─────────────────────────────────────────────────────────────────

func TestMailerErr_NilReturnsNil(t *testing.T) {
	if got := mailerErr("op", nil); got != nil {
		t.Errorf("mailerErr(nil) = %v, want nil", got)
	}
}

func TestMailerErr_PlainError(t *testing.T) {
	inner := errors.New("boom")
	me := mailerErr("dial", inner)
	if me.Op != "dial" {
		t.Errorf("Op = %q, want %q", me.Op, "dial")
	}
	if me.Code != 0 {
		t.Errorf("Code = %d, want 0 for plain error", me.Code)
	}
	if !errors.Is(me, inner) {
		t.Error("should unwrap to inner error")
	}
}

func TestMailerErr_ExtractsSMTPCode(t *testing.T) {
	tpErr := &textproto.Error{Code: 421, Msg: "Service not available"}
	me := mailerErr("send", tpErr)
	if me.Code != 421 {
		t.Errorf("Code = %d, want 421", me.Code)
	}
}

// ── isRetryable (package-level fallback) ──────────────────────────────────────

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context.Canceled", context.Canceled, false},
		{"context.DeadlineExceeded", context.DeadlineExceeded, false},
		{"textproto 421", &textproto.Error{Code: 421}, true},
		{"textproto 550", &textproto.Error{Code: 550}, false},
		{"generic error", errors.New("network reset"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetryable(tt.err); got != tt.want {
				t.Errorf("isRetryable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// ── tlsConfig ─────────────────────────────────────────────────────────────────

func TestTLSConfig(t *testing.T) {
	m := &Mailer{cfg: Config{Host: "smtp.example.com"}}
	cfg := m.tlsConfig()

	if cfg.ServerName != "smtp.example.com" {
		t.Errorf("ServerName = %q, want %q", cfg.ServerName, "smtp.example.com")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2 (%d)", cfg.MinVersion, tls.VersionTLS12)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Error("CipherSuites should not be empty")
	}
	for _, cs := range cfg.CipherSuites {
		// Reject any CBC suite — only AEAD (GCM) suites should be present.
		name := tls.CipherSuiteName(cs)
		if strings.Contains(name, "CBC") {
			t.Errorf("unexpected CBC cipher suite: %s", name)
		}
	}
}

// ── New / Enabled ─────────────────────────────────────────────────────────────

func TestNew_Valid(t *testing.T) {
	m, err := New(testCfg, WithWorkers(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		m.Shutdown(ctx) //nolint:errcheck
	}()
	if !m.Enabled() {
		t.Error("Enabled() = false, want true")
	}
}

func TestNew_DisabledWithEmptyHost(t *testing.T) {
	m, err := New(Config{}) // empty host → disabled stub
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		m.Shutdown(ctx) //nolint:errcheck
	}()
	if m.Enabled() {
		t.Error("Enabled() = true, want false for empty host")
	}
}

func TestNew_InvalidFromAddress(t *testing.T) {
	_, err := New(Config{Host: "smtp.example.com", Port: 587, From: "notanemail"})
	if err == nil {
		t.Fatal("expected error for invalid From, got nil")
	}
}

// ── extractAddr ───────────────────────────────────────────────────────────────

func TestExtractAddr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"User Name <user@example.com>", "user@example.com"},
		{"plain@example.com", "plain@example.com"},
		{"  bare@example.com  ", "bare@example.com"}, // trimmed fallback
	}
	for _, tt := range tests {
		if got := extractAddr(tt.input); got != tt.want {
			t.Errorf("extractAddr(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── generateMessageID ─────────────────────────────────────────────────────────

func TestGenerateMessageID_Format(t *testing.T) {
	id, err := generateMessageID("user@example.com")
	if err != nil {
		t.Fatalf("generateMessageID: %v", err)
	}
	if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, ">") {
		t.Errorf("expected angle-bracket format, got %q", id)
	}
	if !strings.Contains(id, "@example.com") {
		t.Errorf("expected domain in message ID, got %q", id)
	}
}

func TestGenerateMessageID_Uniqueness(t *testing.T) {
	id1, _ := generateMessageID("a@b.com")
	id2, _ := generateMessageID("a@b.com")
	if id1 == id2 {
		t.Error("expected unique IDs, got two identical values")
	}
}

func TestGenerateMessageID_FallbackDomain(t *testing.T) {
	id, err := generateMessageID("nodomain") // no @ in address
	if err != nil {
		t.Fatalf("generateMessageID: %v", err)
	}
	if !strings.HasSuffix(id, "@localhost>") {
		t.Errorf("expected @localhost fallback, got %q", id)
	}
}

// ── buildRaw ──────────────────────────────────────────────────────────────────

func TestBuildRaw_TextOnly(t *testing.T) {
	msg := Message{To: "to@example.com", Subject: "Hi", Text: "Hello"}
	raw, err := buildRaw(testCfg.From, msg)
	if err != nil {
		t.Fatalf("buildRaw: %v", err)
	}
	body := string(raw)
	assertContains(t, body, "Content-Type: text/plain")
	assertContains(t, body, "Content-Transfer-Encoding: quoted-printable")
	assertNotContains(t, body, "Content-Type: text/html")
}

func TestBuildRaw_HTMLOnly(t *testing.T) {
	msg := Message{To: "to@example.com", Subject: "Hi", HTML: "<b>Hello</b>"}
	raw, err := buildRaw(testCfg.From, msg)
	if err != nil {
		t.Fatalf("buildRaw: %v", err)
	}
	body := string(raw)
	assertContains(t, body, "Content-Type: text/html")
	assertContains(t, body, "Content-Transfer-Encoding: quoted-printable")
	assertNotContains(t, body, "multipart/alternative")
}

func TestBuildRaw_Multipart(t *testing.T) {
	msg := Message{
		To:   "to@example.com",
		HTML: "<b>Hello</b>",
		Text: "Hello",
	}
	raw, err := buildRaw(testCfg.From, msg)
	if err != nil {
		t.Fatalf("buildRaw: %v", err)
	}
	body := string(raw)
	assertContains(t, body, "multipart/alternative")
	assertContains(t, body, "text/plain")
	assertContains(t, body, "text/html")
}

func TestBuildRaw_RequiredHeaders(t *testing.T) {
	raw, err := buildRaw(testCfg.From, testMsg)
	if err != nil {
		t.Fatalf("buildRaw: %v", err)
	}
	body := string(raw)
	for _, hdr := range []string{"From:", "To:", "Subject:", "Message-ID:", "Date:", "MIME-Version:", "Auto-Submitted:"} {
		assertContains(t, body, hdr)
	}
}

func TestBuildRaw_InvalidFrom(t *testing.T) {
	_, err := buildRaw("notvalid", testMsg)
	if err == nil {
		t.Fatal("expected error for invalid From address")
	}
}

// ── deliver ───────────────────────────────────────────────────────────────────

func TestDeliver_SuccessNoAuth(t *testing.T) {
	m := &Mailer{cfg: testCfg}
	client := &mockSMTPClient{}
	raw := []byte("Subject: test\r\n\r\nHello")

	if err := m.deliver(client, "to@example.com", raw); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if client.authCalled {
		t.Error("Auth must not be called when Username is empty")
	}
	if client.mailFrom != "from@example.com" {
		t.Errorf("MAIL FROM = %q, want %q", client.mailFrom, "from@example.com")
	}
	if client.rcptTo != "to@example.com" {
		t.Errorf("RCPT TO = %q, want %q", client.rcptTo, "to@example.com")
	}
	if !strings.Contains(client.wc.buf.String(), "Subject: test") {
		t.Error("DATA body was not written to WriteCloser")
	}
}

func TestDeliver_SuccessWithAuth(t *testing.T) {
	cfg := testCfg
	cfg.Username = "user"
	cfg.Password = "secret"
	m := &Mailer{cfg: cfg}
	client := &mockSMTPClient{}

	if err := m.deliver(client, "to@example.com", []byte("test")); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if !client.authCalled {
		t.Error("Auth must be called when Username is set")
	}
}

func TestDeliver_Errors(t *testing.T) {
	plainErr := errors.New("smtp error")
	tpErr550 := &textproto.Error{Code: 550, Msg: "mailbox unavailable"}

	tests := []struct {
		name     string
		cfg      Config
		client   *mockSMTPClient
		wantOp   string
		wantCode int
	}{
		{
			name:   "auth failure",
			cfg:    Config{Host: "h", Port: 1, From: "f@h", Username: "u"},
			client: &mockSMTPClient{authErr: tpErr550},
			wantOp: "auth", wantCode: 550,
		},
		{
			name:   "MAIL FROM failure",
			cfg:    testCfg,
			client: &mockSMTPClient{mailFromErr: plainErr},
			wantOp: "mail-from",
		},
		{
			name:   "RCPT TO failure",
			cfg:    testCfg,
			client: &mockSMTPClient{rcptErr: plainErr},
			wantOp: "rcpt-to",
		},
		{
			name:   "DATA command failure",
			cfg:    testCfg,
			client: &mockSMTPClient{dataErr: plainErr},
			wantOp: "data",
		},
		{
			name:   "write body failure",
			cfg:    testCfg,
			client: &mockSMTPClient{wc: &mockWriteCloser{writeErr: plainErr}},
			wantOp: "write-body",
		},
		{
			name:   "close body failure",
			cfg:    testCfg,
			client: &mockSMTPClient{wc: &mockWriteCloser{closeErr: plainErr}},
			wantOp: "close-body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Mailer{cfg: tt.cfg}
			err := m.deliver(tt.client, "to@example.com", []byte("test"))

			var me *Error
			if !errors.As(err, &me) {
				t.Fatalf("expected *Error, got %T: %v", err, err)
			}
			if me.Op != tt.wantOp {
				t.Errorf("Op = %q, want %q", me.Op, tt.wantOp)
			}
			if tt.wantCode != 0 && me.Code != tt.wantCode {
				t.Errorf("Code = %d, want %d", me.Code, tt.wantCode)
			}
		})
	}
}

// ── sendSTARTTLS ──────────────────────────────────────────────────────────────

func TestSendSTARTTLS_DialError(t *testing.T) {
	m := newTestMailer(t, testCfg, nil)
	dialErr := errors.New("connection refused")
	m.dialSMTP = func(_ context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		return nil, dialErr
	}

	err := m.sendSTARTTLS(context.Background(), "smtp.example.com:587", "to@example.com", []byte("test"))
	assertOpError(t, err, "dial")
}

func TestSendSTARTTLS_STARTTLSNegotiation(t *testing.T) {
	m := newTestMailer(t, testCfg, nil)

	// Extension present and StartTLS succeeds.
	client := &mockSMTPClient{hasSTARTTLS: true}
	m.dialSMTP = func(_ context.Context, _ string, tlsCfg *tls.Config) (smtpClient, error) {
		if tlsCfg != nil {
			t.Error("sendSTARTTLS should dial without TLS config")
		}
		return client, nil
	}

	raw, _ := buildRaw(testCfg.From, testMsg)
	if err := m.sendSTARTTLS(context.Background(), "smtp.example.com:587", testMsg.To, raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendSTARTTLS_STARTTLSError(t *testing.T) {
	m := newTestMailer(t, testCfg, nil)
	tlsErr := errors.New("tls handshake failed")
	client := &mockSMTPClient{hasSTARTTLS: true, startTLSErr: tlsErr}
	m.dialSMTP = func(_ context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		return client, nil
	}

	raw, _ := buildRaw(testCfg.From, testMsg)
	err := m.sendSTARTTLS(context.Background(), "smtp.example.com:587", testMsg.To, raw)
	assertOpError(t, err, "starttls")
}

func TestSendSTARTTLS_QuitErrorPropagatesWhenDeliverSucceeds(t *testing.T) {
	m := newTestMailer(t, testCfg, nil)
	quitErr := errors.New("connection reset")
	client := &mockSMTPClient{quitErr: quitErr}
	m.dialSMTP = func(_ context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		return client, nil
	}

	raw, _ := buildRaw(testCfg.From, testMsg)
	err := m.sendSTARTTLS(context.Background(), "smtp.example.com:587", testMsg.To, raw)
	assertOpError(t, err, "quit")
}

func TestSendSTARTTLS_QuitErrorSuppressedWhenDeliverFails(t *testing.T) {
	m := newTestMailer(t, testCfg, nil)
	client := &mockSMTPClient{
		mailFromErr: errors.New("mail from rejected"),
		quitErr:     errors.New("quit also failed"),
	}
	m.dialSMTP = func(_ context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		return client, nil
	}

	raw, _ := buildRaw(testCfg.From, testMsg)
	err := m.sendSTARTTLS(context.Background(), "smtp.example.com:587", testMsg.To, raw)
	// deliver's error (mail-from) must take precedence over quit.
	assertOpError(t, err, "mail-from")
}

func TestSendTLS_PassesTLSConfigToDial(t *testing.T) {
	m := newTestMailer(t, testCfg, nil)
	var receivedCfg *tls.Config
	client := &mockSMTPClient{}
	m.dialSMTP = func(_ context.Context, _ string, tlsCfg *tls.Config) (smtpClient, error) {
		receivedCfg = tlsCfg
		return client, nil
	}

	raw, _ := buildRaw(testCfg.From, testMsg)
	if err := m.sendTLS(context.Background(), "smtp.example.com:465", testMsg.To, raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedCfg == nil {
		t.Fatal("sendTLS must pass a non-nil TLS config to dialSMTP")
	}
	if receivedCfg.ServerName != testCfg.Host {
		t.Errorf("TLS ServerName = %q, want %q", receivedCfg.ServerName, testCfg.Host)
	}
}

// ── sendWithRetry ─────────────────────────────────────────────────────────────

func TestSendWithRetry_SuccessOnFirstAttempt(t *testing.T) {
	m := newTestMailer(t, testCfg, &mockSMTPClient{})
	if err := m.sendWithRetry(context.Background(), testMsg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendWithRetry_RetriesOnTransientError(t *testing.T) {
	var calls atomic.Int32
	m := newTestMailer(t, testCfg, nil)
	m.dialSMTP = func(_ context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		if calls.Add(1) == 1 {
			// First attempt: temporary 421 → should be retried.
			return &mockSMTPClient{mailFromErr: &textproto.Error{Code: 421, Msg: "try later"}}, nil
		}
		return &mockSMTPClient{}, nil
	}

	if err := m.sendWithRetry(context.Background(), testMsg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("dial calls = %d, want 2", n)
	}
}

func TestSendWithRetry_NoRetryOnPermanentError(t *testing.T) {
	var calls atomic.Int32
	m := newTestMailer(t, testCfg, nil)
	m.dialSMTP = func(_ context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		calls.Add(1)
		// Permanent 550 → must not be retried.
		return &mockSMTPClient{mailFromErr: &textproto.Error{Code: 550, Msg: "no such mailbox"}}, nil
	}

	err := m.sendWithRetry(context.Background(), testMsg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("dial calls = %d, want 1 (no retry on 5xx)", n)
	}
}

func TestSendWithRetry_AllAttemptsExhausted(t *testing.T) {
	m := newTestMailer(t, testCfg, nil)
	m.dialSMTP = func(_ context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		return nil, errors.New("connection refused") // always retryable
	}

	err := m.sendWithRetry(context.Background(), testMsg)
	var me *Error
	if !errors.As(err, &me) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if me.Op != "send" {
		t.Errorf("final error Op = %q, want %q", me.Op, "send")
	}
}

func TestSendWithRetry_ContextCancelledDuringRetryWait(t *testing.T) {
	m := newTestMailer(t, testCfg, nil)
	// Long enough that the wait won't complete before ctx is cancelled.
	m.retryBase = 500 * time.Millisecond
	m.dialSMTP = func(_ context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		return &mockSMTPClient{mailFromErr: &textproto.Error{Code: 421, Msg: "try later"}}, nil
	}

	// The context expires well before the first retry delay (500ms).
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := m.sendWithRetry(ctx, testMsg)
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Errorf("took %v, expected < 400ms (context cancellation should short-circuit wait)", elapsed)
	}

	var me *Error
	if !errors.As(err, &me) || me.Op != "retry-wait" {
		t.Errorf("expected retry-wait *Error, got %v", err)
	}
}

func TestSendWithRetry_UseTLS_PathSelected(t *testing.T) {
	cfg := testCfg
	cfg.UseTLS = true
	m := newTestMailer(t, cfg, nil)

	var gotTLSCfg *tls.Config
	m.dialSMTP = func(_ context.Context, _ string, tlsCfg *tls.Config) (smtpClient, error) {
		gotTLSCfg = tlsCfg
		return &mockSMTPClient{}, nil
	}

	if err := m.sendWithRetry(context.Background(), testMsg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotTLSCfg == nil {
		t.Error("UseTLS=true should dial with a non-nil TLS config")
	}
}

// ── processOne ────────────────────────────────────────────────────────────────

func TestProcessOne_AlreadyCancelledContext(t *testing.T) {
	var (
		errCh = make(chan error, 1)
		m     = &Mailer{
			cfg:       testCfg,
			retryBase: 0,
			dialSMTP:  defaultDialSMTP, // should never be reached
			onErr: func(_ Message, err error) {
				errCh <- err
			},
		}
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before enqueuing

	m.processOne(msgWithContext{msg: testMsg, ctx: ctx})

	select {
	case err := <-errCh:
		var me *Error
		if !errors.As(err, &me) || me.Op != "enqueued-ctx" {
			t.Errorf("expected enqueued-ctx *Error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("onErr was not called within 1s")
	}
}

func TestProcessOne_MergesCallerTimeout(t *testing.T) {
	// The caller context has a 10ms deadline — the send must fail with a
	// context error, not with a dial/network error from the real dialer.
	var (
		errCh = make(chan error, 1)
		m     = &Mailer{
			cfg:       testCfg,
			retryBase: 0,
			onErr: func(_ Message, err error) {
				errCh <- err
			},
		}
	)
	// Mock that hangs until the context is cancelled, simulating a slow dial.
	m.dialSMTP = func(ctx context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	m.processOne(msgWithContext{msg: testMsg, ctx: ctx})

	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Errorf("expected context error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onErr was not called within 2s")
	}
}

// ── Send (disabled) ───────────────────────────────────────────────────────────

func TestSend_DisabledReturnsNil(t *testing.T) {
	m, _ := New(Config{}) // empty host → disabled
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		m.Shutdown(ctx) //nolint:errcheck
	}()
	if err := m.Send(context.Background(), testMsg); err != nil {
		t.Errorf("Send on disabled mailer = %v, want nil", err)
	}
}

// ── Enqueue ───────────────────────────────────────────────────────────────────

func TestEnqueue_DisabledReturnsNil(t *testing.T) {
	m, _ := New(Config{})
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		m.Shutdown(ctx) //nolint:errcheck
	}()
	if err := m.Enqueue(context.Background(), testMsg); err != nil {
		t.Errorf("Enqueue on disabled mailer = %v, want nil", err)
	}
}

func TestEnqueue_AfterShutdownReturnsErrStopped(t *testing.T) {
	m := newTestMailer(t, testCfg, &mockSMTPClient{})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if err := m.Enqueue(context.Background(), testMsg); !errors.Is(err, ErrStopped) {
		t.Errorf("Enqueue after Shutdown = %v, want ErrStopped", err)
	}
}

func TestEnqueue_FullQueueReturnsErrQueueFull(t *testing.T) {
	// Single-slot queue so it fills immediately.
	m, _ := New(testCfg, WithWorkers(1), WithQueueSize(1))
	// Block workers so they don't drain the queue while we're filling it.
	m.dialSMTP = func(ctx context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		<-ctx.Done() // blocks until context is cancelled
		return nil, ctx.Err()
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		m.Shutdown(ctx) //nolint:errcheck
	}()

	// First enqueue fills the slot.
	_ = m.Enqueue(context.Background(), testMsg)
	// Second enqueue must see a full queue.
	if err := m.Enqueue(context.Background(), testMsg); !errors.Is(err, ErrQueueFull) {
		t.Errorf("Enqueue to full queue = %v, want ErrQueueFull", err)
	}
}

// ── Shutdown / drain ──────────────────────────────────────────────────────────

func TestShutdown_DrainsPendingMessages(t *testing.T) {
	var sent atomic.Int32
	m, _ := New(testCfg, WithWorkers(1), WithQueueSize(32))
	m.retryBase = 0
	m.dialSMTP = func(_ context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		sent.Add(1)
		return &mockSMTPClient{}, nil
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.Shutdown(ctx) //nolint:errcheck
	}()

	const n = 8
	for i := 0; i < n; i++ {
		if err := m.Enqueue(context.Background(), testMsg); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if got := sent.Load(); got != n {
		t.Errorf("sent = %d, want %d (Shutdown should drain all queued messages)", got, n)
	}
}

func TestShutdown_TimeoutReturnsError(t *testing.T) {
	unblock := make(chan struct{})
	m, _ := New(testCfg, WithWorkers(1), WithQueueSize(4))
	m.retryBase = 0
	m.dialSMTP = func(ctx context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		select {
		case <-unblock:
		case <-ctx.Done():
		}
		return nil, errors.New("blocked")
	}
	defer close(unblock)

	// Give the worker something to chew on.
	_ = m.Enqueue(context.Background(), testMsg)

	// Give the worker time to pick up the message before we shut down.
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := m.Shutdown(ctx)
	if err == nil {
		t.Fatal("expected Shutdown to time out, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Shutdown error = %v, want DeadlineExceeded", err)
	}
}

func TestShutdown_IdempotentMultipleCalls(t *testing.T) {
	m := newTestMailer(t, testCfg, &mockSMTPClient{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	// Second call must not panic (once.Do protects against double-close).
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

// ── Race: concurrent Enqueue / Shutdown ───────────────────────────────────────

func TestRace_ConcurrentEnqueueAndShutdown(t *testing.T) {
	m, err := New(testCfg, WithWorkers(2), WithQueueSize(64))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.retryBase = 0
	m.dialSMTP = func(_ context.Context, _ string, _ *tls.Config) (smtpClient, error) {
		return &mockSMTPClient{}, nil
	}

	var wg sync.WaitGroup
	// 10 goroutines firing Enqueue concurrently with Shutdown.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				err := m.Enqueue(context.Background(), testMsg)
				// ErrStopped and ErrQueueFull are expected under load; anything
				// else is a bug.
				if err != nil && !errors.Is(err, ErrStopped) && !errors.Is(err, ErrQueueFull) {
					t.Errorf("unexpected Enqueue error: %v", err)
				}
			}
		}()
	}

	// Let goroutines get started before pulling the rug.
	time.Sleep(5 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if sErr := m.Shutdown(ctx); sErr != nil {
		t.Errorf("Shutdown: %v", sErr)
	}

	wg.Wait()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func assertContains(t *testing.T, body, substr string) {
	t.Helper()
	if !strings.Contains(body, substr) {
		t.Errorf("expected body to contain %q", substr)
	}
}

func assertNotContains(t *testing.T, body, substr string) {
	t.Helper()
	if strings.Contains(body, substr) {
		t.Errorf("expected body NOT to contain %q", substr)
	}
}

func assertOpError(t *testing.T, err error, wantOp string) {
	t.Helper()
	var me *Error
	if !errors.As(err, &me) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if me.Op != wantOp {
		t.Errorf("Error.Op = %q, want %q", me.Op, wantOp)
	}
}
