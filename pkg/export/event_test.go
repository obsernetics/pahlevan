package export

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 14, 10, 30, 0, 123456789, time.UTC)

func TestProtocolNames(t *testing.T) {
	cases := map[uint8]string{1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6", 132: "sctp", 200: "proto_200"}
	for proto, want := range cases {
		if got := protocolName(proto); got != want {
			t.Errorf("protocolName(%d) = %q, want %q", proto, got, want)
		}
	}
}

func TestEventJSONShape(t *testing.T) {
	ev := &Event{
		Version:    SchemaVersion,
		Timestamp:  Timestamp(testNow),
		Type:       EventTypeFile,
		Action:     ActionDeny,
		CgroupID:   1,
		Process:    ProcessInfo{PID: 3, Comm: "curl"},
		File:       &FileInfo{Path: "/etc/passwd"},
		Kubernetes: &KubernetesRef{Namespace: "prod", Pod: "api-0", Container: "api"},
	}

	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["timestamp"] != "2026-08-14T10:30:00.123456789Z" {
		t.Errorf("timestamp = %v, want RFC3339Nano", decoded["timestamp"])
	}
	if decoded["type"] != "file" || decoded["action"] != "deny" {
		t.Errorf("type/action = %v/%v", decoded["type"], decoded["action"])
	}
	if _, ok := decoded["network"]; ok {
		t.Error("network block must be omitted for a file event")
	}
	k, ok := decoded["kubernetes"].(map[string]any)
	if !ok || k["namespace"] != "prod" || k["pod"] != "api-0" {
		t.Errorf("kubernetes = %v", decoded["kubernetes"])
	}

	// Round trip back into the envelope.
	var back Event
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if !back.Timestamp.Time().Equal(testNow) || back.File.Path != "/etc/passwd" {
		t.Errorf("round tripped event = %+v", back)
	}
}

func TestTimestampUnmarshalErrors(t *testing.T) {
	var ts Timestamp
	if err := ts.UnmarshalJSON([]byte(`"not a time"`)); err == nil {
		t.Error("expected an error for a malformed timestamp")
	}
	if err := ts.UnmarshalJSON([]byte(`7`)); err == nil {
		t.Error("expected an error for a non string timestamp")
	}
	if got := Timestamp(testNow).String(); got != "2026-08-14T10:30:00.123456789Z" {
		t.Errorf("String() = %q", got)
	}
}

func TestParseEventType(t *testing.T) {
	for _, name := range []string{"syscall", " FILE ", "network", "process", "capability"} {
		if _, err := ParseEventType(name); err != nil {
			t.Errorf("ParseEventType(%q) failed: %v", name, err)
		}
	}
	if _, err := ParseEventType("dns"); err == nil {
		t.Error("expected an error for an unknown type")
	} else if !strings.Contains(err.Error(), "syscall") {
		t.Errorf("error should list the valid types, got %v", err)
	}
	if got := EventTypeNames(); !strings.Contains(got, "network") {
		t.Errorf("EventTypeNames() = %q", got)
	}
}

func TestKubernetesRefEmpty(t *testing.T) {
	var nilRef *KubernetesRef
	if !nilRef.Empty() {
		t.Error("nil ref should be empty")
	}
	if !(&KubernetesRef{}).Empty() {
		t.Error("zero ref should be empty")
	}
	if (&KubernetesRef{Runtime: "containerd"}).Empty() {
		t.Error("ref with a runtime is not empty")
	}
}

func TestSyscallNameFallback(t *testing.T) {
	// Numbers outside the generated table render numerically on every
	// platform, including the ones that have no table at all.
	if got := SyscallName(1 << 40); got != "syscall_1099511627776" {
		t.Errorf("unknown syscall rendered as %q", got)
	}
}
