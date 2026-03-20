package oauth

import (
	"net/url"
	"strings"
)

// redirectKind classifies the post-login destination so the handler can choose
// between the web (cookie + 303 redirect) and mobile (one-time code + redirect)
// response strategies without duplicating URL-parsing logic.
type redirectKind uint8

const (
	redirectKindNone   redirectKind = iota // empty — use legacy JSON response
	redirectKindWeb                        // https:// with hostname  → cookie path
	redirectKindMobile                     // custom scheme           → one-time code path
)

// classifyRedirect returns the redirect kind for rawURL.
//
//   - Empty string         → redirectKindNone  (backward-compat: return JSON)
//   - https:// + hostname  → redirectKindWeb
//   - any other non-http(s)→ redirectKindMobile  (com.app:/, myapp://…)
//   - http://              → redirectKindNone   (never allowed)
func classifyRedirect(rawURL string) redirectKind {
	if rawURL == "" {
		return redirectKindNone
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return redirectKindNone
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
		if u.Hostname() != "" {
			return redirectKindWeb
		}
		return redirectKindNone
	case "http":
		return redirectKindNone // plain HTTP never allowed
	case "":
		return redirectKindNone
	default:
		// Any non-http(s) scheme (com.myapp, myapp, exp, …) = mobile deep-link.
		return redirectKindMobile
	}
}

// isWebRedirect reports whether rawURL is a valid HTTPS URL with a hostname.
func isWebRedirect(rawURL string) bool {
	return classifyRedirect(rawURL) == redirectKindWeb
}

// isCustomScheme reports whether rawURL uses a non-http(s) scheme.
// Custom schemes (e.g. com.myapp://oauth/callback) are the mobile deep-link pattern.
func isCustomScheme(rawURL string) bool {
	return classifyRedirect(rawURL) == redirectKindMobile
}

// appendQueryParam adds key=value to rawURL preserving any existing query string.
// Safe for both https:// and custom-scheme URIs.
func appendQueryParam(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		return rawURL + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// normaliseRedirect returns a canonical lowercase string for allowlist comparison.
// Web URLs strip the trailing slash; custom-scheme URIs are fully lowercased.
func normaliseRedirect(rawURL string) string {
	if isCustomScheme(rawURL) {
		return strings.ToLower(strings.TrimRight(rawURL, "/"))
	}
	return normaliseURL(rawURL) // existing helper for https:// URLs
}
