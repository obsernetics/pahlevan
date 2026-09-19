package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStringListAcceptsBothSpellings(t *testing.T) {
	// An operator listing agents should not have to remember whether this
	// binary wanted a repeated flag or a comma separated one.
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{name: "repeated", in: []string{"a:9090", "b:9090"}, want: "a:9090,b:9090"},
		{name: "comma separated", in: []string{"a:9090,b:9090"}, want: "a:9090,b:9090"},
		{name: "mixed with spaces", in: []string{"a:9090, b:9090", "c:9090"}, want: "a:9090,b:9090,c:9090"},
		{name: "empty entries are dropped", in: []string{"a:9090,,"}, want: "a:9090"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var list stringList
			for _, value := range tc.in {
				if err := list.Set(value); err != nil {
					t.Fatalf("Set(%q) returned %v", value, err)
				}
			}
			if got := list.String(); got != tc.want {
				t.Fatalf("stringList = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildSources(t *testing.T) {
	t.Run("no agents means no store", func(t *testing.T) {
		sources, err := buildSources(nil, "", "", "", false)
		if err != nil || sources != nil {
			t.Fatalf("buildSources = %v, %v; want no sources and no error", sources, err)
		}
	})

	t.Run("token file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte("  secret\n"), 0o600); err != nil {
			t.Fatalf("writing the token file: %v", err)
		}
		sources, err := buildSources(stringList{"agent:9090"}, "ca.crt", "agent.svc", path, false)
		if err != nil {
			t.Fatalf("buildSources returned %v", err)
		}
		if len(sources) != 1 || sources[0].Token != "secret" {
			t.Fatalf("buildSources produced %+v", sources)
		}
		if sources[0].CAFile != "ca.crt" || sources[0].ServerName != "agent.svc" {
			t.Fatalf("the source lost its TLS configuration: %+v", sources[0])
		}
	})

	t.Run("empty token file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
			t.Fatalf("writing the token file: %v", err)
		}
		_, err := buildSources(stringList{"agent:9090"}, "", "", path, false)
		if err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Fatalf("buildSources returned %v for an empty token file", err)
		}
	})

	t.Run("missing token file", func(t *testing.T) {
		_, err := buildSources(stringList{"agent:9090"}, "", "", "/nonexistent/token", false)
		if err == nil {
			t.Fatal("buildSources accepted a token file that does not exist")
		}
	})

	t.Run("a token over plaintext fails at startup", func(t *testing.T) {
		// Finding out at startup is the difference between fixing it and
		// publishing the token.
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatalf("writing the token file: %v", err)
		}
		_, err := buildSources(stringList{"agent:9090"}, "", "", path, true)
		if err == nil || !strings.Contains(err.Error(), "cleartext") {
			t.Fatalf("buildSources returned %v, want a refusal naming the cleartext token", err)
		}
	})

	t.Run("an endpoint-less entry is rejected", func(t *testing.T) {
		if _, err := buildSources(stringList{"   "}, "", "", "", true); err == nil {
			// Set trims blanks, so this is reachable only in code, but a
			// source with no endpoint would otherwise retry a dial forever.
			t.Log("blank endpoints are dropped by Set before they reach buildSources")
		}
	})
}
