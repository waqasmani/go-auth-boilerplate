package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

const (
	dialTimeout      = 10 * time.Second
	smtpTimeout      = 30 * time.Second
	defaultRetryBase = 500 * time.Millisecond
	maxRetries       = 3
)

const (
	defaultWorkers   = 4
	defaultQueueSize = 256
	workerMsgTimeout = 3 * time.Minute
)

var (
	ErrQueueFull = errors.New("mailer: send queue is full")
	ErrStopped   = errors.New("mailer: mailer has been shut down")
)

// ── Typed errors ──────────────────────────────────────────────────────────────

// Error is a structured error that carries the failed SMTP operation, the
// underlying cause, and — when the failure originated at the SMTP layer — the
// server's numeric reply code. Call IsRetryable to decide whether the send
// should be attempted again.
type Error struct {
	// Op is the logical operation that failed ("auth", "dial", "send", …).
	Op string
	// Err is the underlying cause; preserved for errors.Is / errors.As.
	Err error
	// Code is the SMTP reply code (e.g. 421, 550). Zero when not applicable.
	Code int
}

func (e *Error) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("mailer: %s (smtp %d): %v", e.Op, e.Code, e.Err)
	}
	return fmt.Sprintf("mailer: %s: %v", e.Op, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// IsRetryable reports whether the failure is transient. SMTP reply codes
// below 500 are temporary; permanent failures and context errors are not.
func (e *Error) IsRetryable() bool {
	if errors.Is(e.Err, context.Canceled) || errors.Is(e.Err, context.DeadlineExceeded) {
		return false
	}
	if e.Code != 0 {
		return e.Code < 500
	}
	return true
}

// mailerErr wraps err in an *Error labelled with op. If err contains a
// *textproto.Error its numeric code is extracted automatically.
func mailerErr(op string, err error) *Error {
	if err == nil {
		return nil
	}
	me := &Error{Op: op, Err: err}
	var tpErr *textproto.Error
	if errors.As(err, &tpErr) {
		me.Code = tpErr.Code
	}
	return me
}

// ── SMTP client interface ─────────────────────────────────────────────────────

// smtpClient is the subset of *smtp.Client used by this package. Abstracting
// it into an interface allows test doubles to operate without a real SMTP
// server.
type smtpClient interface {
	Extension(name string) (bool, string)
	StartTLS(config *tls.Config) error
	Auth(a smtp.Auth) error
	Mail(from string) error
	Rcpt(to string) error
	Data() (io.WriteCloser, error)
	Quit() error
	Close() error
}

// defaultDialSMTP establishes a connection to addr and wraps it in an
// smtpClient. When tlsCfg is non-nil the connection is opened over implicit
// TLS (port 465 style); when nil a plain TCP connection is opened and
// STARTTLS may be negotiated afterwards by the caller.
func defaultDialSMTP(ctx context.Context, addr string, tlsCfg *tls.Config) (smtpClient, error) {
	host, _, _ := net.SplitHostPort(addr)

	var (
		conn net.Conn
		err  error
	)
	if tlsCfg != nil {
		conn, err = (&tls.Dialer{
			NetDialer: &net.Dialer{Timeout: dialTimeout},
			Config:    tlsCfg,
		}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}

	if dErr := conn.SetDeadline(time.Now().Add(smtpTimeout)); dErr != nil {
		_ = conn.Close()
		return nil, dErr
	}

	c, cErr := smtp.NewClient(conn, host)
	if cErr != nil {
		_ = conn.Close()
		return nil, cErr
	}
	return c, nil
}

// ── Config ────────────────────────────────────────────────────────────────────

// Config holds the SMTP connection parameters. Password should be sourced from
// an environment variable at startup and must never be logged or persisted.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	UseTLS   bool
}

// Message is a single outbound email.
type Message struct {
	To      string
	Subject string
	HTML    string
	Text    string
}

// msgWithContext pairs a Message with the context supplied by the enqueuing
// caller so that workers can honour its deadline or cancellation signal.
type msgWithContext struct {
	msg Message
	ctx context.Context
}

// ── Options ───────────────────────────────────────────────────────────────────

type options struct {
	workers   int
	queueSize int
	onErr     func(Message, error)
}

// Option configures a Mailer.
type Option func(*options)

// WithWorkers sets the number of background send goroutines (default 4).
func WithWorkers(n int) Option {
	return func(o *options) {
		if n > 0 {
			o.workers = n
		}
	}
}

// WithQueueSize sets the capacity of the async send queue (default 256).
func WithQueueSize(n int) Option {
	return func(o *options) {
		if n > 0 {
			o.queueSize = n
		}
	}
}

// WithErrorHandler registers a callback invoked whenever an async send fails.
// The callback runs synchronously inside the worker goroutine.
func WithErrorHandler(fn func(Message, error)) Option {
	return func(o *options) {
		if fn != nil {
			o.onErr = fn
		}
	}
}

// ── Mailer ────────────────────────────────────────────────────────────────────

// Mailer sends transactional email via SMTP. Use New to construct one;
// the zero value is not usable.
type Mailer struct {
	cfg   Config
	queue chan msgWithContext
	done  chan struct{}
	wg    sync.WaitGroup
	once  sync.Once
	// mu serialises the stopped flag. Enqueue holds a read lock for its
	// entire check-and-send sequence; Shutdown holds the write lock before
	// closing done, eliminating the TOCTOU window between the two operations.
	mu      sync.RWMutex
	stopped bool
	onErr   func(Message, error)

	// finished is closed by the single drain goroutine that Shutdown starts
	// exactly once (inside once.Do). Every Shutdown caller — including
	// concurrent or repeated callers — selects on this shared channel rather
	// than constructing a new one per call.
	//
	// Why a struct field instead of a local variable:
	//
	// If Shutdown is called twice and the first caller times out, it spawns a
	// goroutine (wg.Wait → close(localFinished)) that outlives the first call.
	// The second caller constructs its own goroutine and its own local channel.
	// Now two goroutines race on wg.Wait; when workers finish, both goroutines
	// unblock and each closes its own local channel — the second caller waits
	// on the correct channel, but the first caller's goroutine leaks until
	// wg.Wait returns and then closes a channel no one reads. With more
	// Shutdown calls (e.g. repeated deferred cleanup), goroutines accumulate.
	//
	// With a struct-field channel started once inside once.Do, there is
	// exactly one drain goroutine for the lifetime of the Mailer. A caller
	// whose ctx expires returns an error but does not leak a goroutine.
	// The next Shutdown call selects on the same m.finished and honours its
	// own ctx deadline correctly.
	finished chan struct{}

	// retryBase is the initial back-off delay before the first retry.
	// It defaults to defaultRetryBase and may be set to zero in tests to
	// make retry loops instant without changing any observable behaviour.
	retryBase time.Duration

	// dialSMTP creates a connected smtpClient for the given address. A nil
	// tlsCfg means plain TCP; a non-nil tlsCfg means implicit TLS. Defaults
	// to defaultDialSMTP; replaced by a mock factory in unit tests.
	dialSMTP func(ctx context.Context, addr string, tlsCfg *tls.Config) (smtpClient, error)
}

// New constructs a Mailer from cfg and starts its worker goroutines.
// It returns an error if cfg.From is not a valid RFC 5322 address (only
// checked when cfg.Host is set; a mailer with an empty Host is a valid
// disabled stub).
func New(cfg Config, opts ...Option) (*Mailer, error) {
	o := options{
		workers:   defaultWorkers,
		queueSize: defaultQueueSize,
		onErr:     func(_ Message, _ error) {},
	}
	for _, opt := range opts {
		opt(&o)
	}

	if cfg.Host != "" {
		if _, err := mail.ParseAddress(cfg.From); err != nil {
			return nil, fmt.Errorf("mailer: invalid From address %q: %w", cfg.From, err)
		}
	}

	m := &Mailer{
		cfg:       cfg,
		queue:     make(chan msgWithContext, o.queueSize),
		done:      make(chan struct{}),
		finished:  make(chan struct{}),
		onErr:     o.onErr,
		retryBase: defaultRetryBase,
		dialSMTP:  defaultDialSMTP,
	}

	for i := 0; i < o.workers; i++ {
		m.wg.Add(1)
		go m.worker()
	}

	return m, nil
}

// Enabled reports whether the mailer is configured to send email.
// A Mailer with an empty Host silently discards all messages, which is
// useful in environments where email is not required.
func (m *Mailer) Enabled() bool { return m.cfg.Host != "" }

// Send delivers msg synchronously, honouring ctx for cancellation and
// deadline. It returns nil immediately when the mailer is disabled.
func (m *Mailer) Send(ctx context.Context, msg Message) error {
	if !m.Enabled() {
		return nil
	}
	return m.sendWithRetry(ctx, msg)
}

// Enqueue adds msg to the background send queue. ctx is propagated to the
// worker so that a cancelled or timed-out caller context can abort the send
// before it reaches the network.
//
// Enqueue returns ErrStopped after Shutdown has been called, and ErrQueueFull
// when the queue has no remaining capacity.
func (m *Mailer) Enqueue(ctx context.Context, msg Message) error {
	if !m.Enabled() {
		return nil
	}

	// Hold the read lock for the entire check-and-send sequence so that
	// Shutdown cannot close done and drain workers between our stopped check
	// and our channel write.
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.stopped {
		return ErrStopped
	}

	select {
	case m.queue <- msgWithContext{msg: msg, ctx: ctx}:
		return nil
	default:
		return ErrQueueFull
	}
}

// Shutdown signals workers to stop accepting new messages and waits until all
// in-flight and queued sends are complete, or until ctx is cancelled.
//
// It is safe to call Shutdown concurrently or repeatedly. The first call
// closes m.done (signalling all workers) and starts a single drain goroutine
// that closes m.finished when all workers have exited. Every call — including
// the first — then selects on that shared channel:
//
//   - If drain completes before ctx expires → return nil.
//   - If ctx expires first → return a timeout error.
//
// Importantly, a timed-out first caller does not spawn any lingering goroutine.
// The drain goroutine started inside once.Do runs to completion regardless of
// how many Shutdown callers have already returned, so the next caller that
// provides a sufficient deadline will see the correct outcome.
func (m *Mailer) Shutdown(ctx context.Context) error {
	m.once.Do(func() {
		// Phase 1: prevent new Enqueue calls and signal workers to drain.
		// The write lock must span both mutations. Releasing it early would
		// reopen the TOCTOU window that the RLock in Enqueue is designed to
		// close.
		m.mu.Lock()
		m.stopped = true
		close(m.done)
		m.mu.Unlock()

		// Phase 2: start exactly one drain goroutine. It waits for all workers
		// to finish their current send and the drain loop, then closes
		// m.finished so every Shutdown caller — present and future — unblocks.
		//
		// This goroutine is started inside once.Do so it runs exactly once per
		// Mailer lifetime. Subsequent Shutdown calls skip this block entirely
		// and proceed directly to the select below, where they wait on the same
		// m.finished channel.
		go func() {
			m.wg.Wait()
			close(m.finished)
		}()
	})

	select {
	case <-m.finished:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("mailer: shutdown timed out: %w", ctx.Err())
	}
}

// ── Worker ────────────────────────────────────────────────────────────────────

func (m *Mailer) worker() {
	defer m.wg.Done()
	for {
		select {
		case item := <-m.queue:
			m.processOne(item)
		case <-m.done:
			// Drain messages that arrived before the shutdown signal.
			for {
				select {
				case item := <-m.queue:
					m.processOne(item)
				default:
					return
				}
			}
		}
	}
}

// processOne sends a single queued message. It merges the enqueuing caller's
// context with the per-message worker timeout so that either side may abort
// the send.
func (m *Mailer) processOne(item msgWithContext) {
	// Bail immediately if the caller's context is already done; no point
	// opening a connection for a request that has already timed out.
	if err := item.ctx.Err(); err != nil {
		m.onErr(item.msg, mailerErr("enqueued-ctx", err))
		return
	}

	// The send is cancelled when *either* the caller's deadline expires or the
	// per-message worker timeout fires, whichever comes first.
	ctx, cancel := context.WithTimeout(item.ctx, workerMsgTimeout)
	defer cancel()

	if err := m.sendWithRetry(ctx, item.msg); err != nil {
		m.onErr(item.msg, err)
	}
}

// ── TLS ───────────────────────────────────────────────────────────────────────

// tlsConfig returns a *tls.Config used by both sendSTARTTLS and sendTLS.
// Centralising the config ensures the two code paths are always consistent.
// TLS 1.2 is the minimum; only AEAD cipher suites are allowed.
func (m *Mailer) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName: m.cfg.Host,
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

// ── Send path ─────────────────────────────────────────────────────────────────

func (m *Mailer) sendWithRetry(ctx context.Context, msg Message) error {
	raw, err := buildRaw(m.cfg.From, msg)
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)

	var lastErr error
	for attempt := range maxRetries {
		// Check cancellation before any work on this attempt — including
		// attempt 0. Without this, a cancelled context on the first attempt
		// reaches sendTLS/sendSTARTTLS and produces an opaque TCP dial error
		// instead of a clean context.Canceled / context.DeadlineExceeded.
		if err := ctx.Err(); err != nil {
			return mailerErr("send-ctx", err)
		}
		if attempt > 0 {
			delay := m.retryBase * time.Duration(1<<(attempt-1))
			select {
			case <-ctx.Done():
				return mailerErr("retry-wait", ctx.Err())
			case <-time.After(delay):
			}
		}

		if m.cfg.UseTLS {
			lastErr = m.sendTLS(ctx, addr, msg.To, raw)
		} else {
			lastErr = m.sendSTARTTLS(ctx, addr, msg.To, raw)
		}

		if lastErr == nil {
			return nil
		}

		var me *Error
		if errors.As(lastErr, &me) {
			if !me.IsRetryable() {
				return lastErr
			}
		} else if !isRetryable(lastErr) {
			return lastErr
		}
	}
	return &Error{Op: "send", Err: fmt.Errorf("%d attempts failed: %w", maxRetries, lastErr)}
}

func (m *Mailer) sendSTARTTLS(ctx context.Context, addr, to string, raw []byte) (err error) {
	c, dialErr := m.dialSMTP(ctx, addr, nil)
	if dialErr != nil {
		return mailerErr("dial", dialErr)
	}
	defer func() {
		if qErr := c.Quit(); qErr != nil && err == nil {
			err = mailerErr("quit", qErr)
		}
	}()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(m.tlsConfig()); err != nil {
			return mailerErr("starttls", err)
		}
	}
	return m.deliver(c, to, raw)
}

func (m *Mailer) sendTLS(ctx context.Context, addr, to string, raw []byte) (err error) {
	c, dialErr := m.dialSMTP(ctx, addr, m.tlsConfig())
	if dialErr != nil {
		return mailerErr("tls-dial", dialErr)
	}
	defer func() {
		if qErr := c.Quit(); qErr != nil && err == nil {
			err = mailerErr("quit", qErr)
		}
	}()
	return m.deliver(c, to, raw)
}

// deliver performs authentication (when configured) and executes the SMTP
// DATA exchange on an already-connected c.
func (m *Mailer) deliver(c smtpClient, to string, raw []byte) error {
	if m.cfg.Username != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return mailerErr("auth", err)
		}
	}
	if err := c.Mail(extractAddr(m.cfg.From)); err != nil {
		return mailerErr("mail-from", err)
	}
	if err := c.Rcpt(to); err != nil {
		return mailerErr("rcpt-to", err)
	}
	wc, err := c.Data()
	if err != nil {
		return mailerErr("data", err)
	}
	if _, err = wc.Write(raw); err != nil {
		return mailerErr("write-body", err)
	}
	if err = wc.Close(); err != nil {
		return mailerErr("close-body", err)
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func extractAddr(s string) string {
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return strings.TrimSpace(s)
	}
	return addr.Address
}

// isRetryable is a fallback for errors that were not wrapped as *Error.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var tpErr *textproto.Error
	if errors.As(err, &tpErr) {
		return tpErr.Code < 500
	}
	return true
}

// ── Message building ──────────────────────────────────────────────────────────

// buildRaw serialises msg into a standards-compliant RFC 5322 byte slice
// ready to be written to the SMTP DATA stream.
//
// All three paths — multipart, HTML-only, and text-only — encode the body as
// quoted-printable, satisfying the RFC 5321 §4.5.3 998-character line limit
// that HTML emails routinely exceed without encoding.
func buildRaw(from string, msg Message) ([]byte, error) {
	fromAddr, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("mailer: parse From: %w", err)
	}
	msgID, err := generateMessageID(fromAddr.Address)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	hdr := func(k, v string) { fmt.Fprintf(&buf, "%s: %s\r\n", k, v) }

	hdr("From", from)
	hdr("To", msg.To)
	hdr("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	hdr("Message-ID", msgID)
	hdr("Date", time.Now().UTC().Format(time.RFC1123Z))
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")

	switch {
	case msg.HTML != "" && msg.Text != "":
		boundary, body, err := buildMultipartBody(msg)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
		buf.Write(body)
		return buf.Bytes(), nil
	case msg.HTML != "":
		hdr("Content-Type", `text/html; charset="utf-8"`)
		hdr("Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		qpw := quotedprintable.NewWriter(&buf)
		if _, err = qpw.Write([]byte(msg.HTML)); err != nil {
			return nil, fmt.Errorf("mailer: write html body: %w", err)
		}
		if err = qpw.Close(); err != nil {
			return nil, fmt.Errorf("mailer: close html qp writer: %w", err)
		}
	default:
		hdr("Content-Type", `text/plain; charset="utf-8"`)
		hdr("Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		qpw := quotedprintable.NewWriter(&buf)
		if _, err = qpw.Write([]byte(msg.Text)); err != nil {
			return nil, fmt.Errorf("mailer: write text body: %w", err)
		}
		if err = qpw.Close(); err != nil {
			return nil, fmt.Errorf("mailer: close text qp writer: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// buildMultipartBody encodes msg as a multipart/alternative MIME body and
// returns the boundary string and the raw body bytes. Callers are responsible
// for writing the outer Content-Type header using the returned boundary.
func buildMultipartBody(msg Message) (boundary string, body []byte, err error) {
	var bodyBuf bytes.Buffer
	mw := multipart.NewWriter(&bodyBuf)

	writePart := func(contentType, content string) error {
		pw, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {contentType + `; charset="utf-8"`},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return err
		}
		qpw := quotedprintable.NewWriter(pw)
		if _, err = qpw.Write([]byte(content)); err != nil {
			return err
		}
		return qpw.Close()
	}

	if err := writePart("text/plain", msg.Text); err != nil {
		return "", nil, fmt.Errorf("mailer: write text part: %w", err)
	}
	if err := writePart("text/html", msg.HTML); err != nil {
		return "", nil, fmt.Errorf("mailer: write html part: %w", err)
	}
	if err := mw.Close(); err != nil {
		return "", nil, fmt.Errorf("mailer: close multipart writer: %w", err)
	}

	return mw.Boundary(), bodyBuf.Bytes(), nil
}

func generateMessageID(fromAddr string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mailer: generate message ID: %w", err)
	}
	domain := "localhost"
	if i := strings.LastIndex(fromAddr, "@"); i != -1 {
		domain = fromAddr[i+1:]
	}
	return fmt.Sprintf("<%s@%s>", hex.EncodeToString(b), domain), nil
}
