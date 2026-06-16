package config

import "testing"

func TestValidateTrustedProxies(t *testing.T) {
	cases := []struct {
		name    string
		env     string
		cidrs   []string
		wantErr bool
	}{
		{"dev empty ok", "development", nil, false},
		{"prod empty rejected", "production", nil, true},
		{"prod trust-all v4 rejected", "production", []string{"0.0.0.0/0"}, true},
		{"prod trust-all v6 rejected", "production", []string{"::/0"}, true},
		{"prod valid cidr ok", "production", []string{"10.0.0.0/8"}, false},
		{"prod valid ip ok", "production", []string{"192.168.1.1"}, false},
		{"prod garbage rejected", "production", []string{"not-a-cidr"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTrustedProxies(&Config{AppEnv: tc.env, TrustedProxyCIDRs: tc.cidrs})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateSecretStrength(t *testing.T) {
	strong := "Qk9j3v8sZ2pX1mW7tR4yU0aB6cD5eF2gH9iJ1kL3nM" // 42 distinct-ish base64 chars

	t.Run("dev skips checks", func(t *testing.T) {
		c := &Config{AppEnv: "development", JWTKeys: []JWTKeyConfig{{ID: "v1", Secret: "change-me-please-32-bytes-aaaaaaaaaa"}}, OTPSecret: strong}
		if err := validateSecretStrength(c); err != nil {
			t.Fatalf("dev should skip: %v", err)
		}
	})

	t.Run("prod rejects placeholder", func(t *testing.T) {
		c := &Config{
			AppEnv:    "production",
			JWTKeys:   []JWTKeyConfig{{ID: "v1", Secret: "change-me-in-production-use-a-long-random-secret"}},
			OTPSecret: strong,
		}
		if err := validateSecretStrength(c); err == nil {
			t.Fatal("placeholder JWT secret accepted in production")
		}
	})

	t.Run("prod rejects low entropy", func(t *testing.T) {
		c := &Config{
			AppEnv:    "production",
			JWTKeys:   []JWTKeyConfig{{ID: "v1", Secret: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
			OTPSecret: strong,
		}
		if err := validateSecretStrength(c); err == nil {
			t.Fatal("low-entropy JWT secret accepted in production")
		}
	})

	t.Run("prod accepts strong", func(t *testing.T) {
		c := &Config{
			AppEnv:    "production",
			JWTKeys:   []JWTKeyConfig{{ID: "v1", Secret: strong}},
			OTPSecret: strong,
		}
		if err := validateSecretStrength(c); err != nil {
			t.Fatalf("strong secrets rejected: %v", err)
		}
	})
}

func TestValidateCORSOrigins_WildcardWithCredentials(t *testing.T) {
	bad := &Config{AppEnv: "production", CORSAllowCredentials: true, CORSAllowedOrigins: []string{"https://*.example.com"}}
	if err := validateCORSOrigins(bad); err == nil {
		t.Fatal("wildcard origin with credentials was accepted")
	}
	ok := &Config{AppEnv: "production", CORSAllowCredentials: true, CORSAllowedOrigins: []string{"https://app.example.com"}}
	if err := validateCORSOrigins(ok); err != nil {
		t.Fatalf("exact origin rejected: %v", err)
	}
}

func TestValidateDBSecurity(t *testing.T) {
	cases := []struct {
		name          string
		env           string
		dsn           string
		allowInsecure bool
		wantErr       bool
	}{
		{"dev skips", "development", "u:p@tcp(h:3306)/db", false, false},
		{"prod no tls rejected", "production", "u:p@tcp(h:3306)/db?parseTime=true", false, true},
		{"prod tls=true ok", "production", "u:p@tcp(h:3306)/db?tls=true", false, false},
		{"prod tls=false rejected", "production", "u:p@tcp(h:3306)/db?tls=false", false, true},
		{"prod insecure-ack ok", "production", "u:p@tcp(h:3306)/db", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDBSecurity(&Config{AppEnv: tc.env, DBDSN: tc.dsn, DBAllowInsecure: tc.allowInsecure})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
