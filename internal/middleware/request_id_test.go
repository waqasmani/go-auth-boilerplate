package middleware

import "testing"

func TestSanitizeRequestID(t *testing.T) {
	long := make([]byte, maxRequestIDLen+1)
	for i := range long {
		long[i] = 'a'
	}

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"uuid kept", "550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000"},
		{"alnum dot underscore kept", "req_1.A-2", "req_1.A-2"},
		{"empty rejected", "", ""},
		{"too long rejected", string(long), ""},
		{"newline rejected", "abc\ndef", ""},
		{"space rejected", "abc def", ""},
		{"slash rejected", "abc/def", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeRequestID(tc.in); got != tc.want {
				t.Fatalf("sanitizeRequestID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
