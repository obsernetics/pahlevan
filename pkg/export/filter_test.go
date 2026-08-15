package export

import "testing"

func TestNewFilterRejectsUnknownType(t *testing.T) {
	if _, err := NewFilter([]string{"file", "dns"}, false); err == nil {
		t.Fatal("expected an error for an unknown type")
	}
	f, err := NewFilter([]string{"", "file"}, false)
	if err != nil {
		t.Fatalf("empty names should be ignored: %v", err)
	}
	if !f.AllowType(EventTypeFile) || f.AllowType(EventTypeSyscall) {
		t.Errorf("filter = %+v", f)
	}
	if f.Allow(nil) {
		t.Error("a nil event never passes")
	}
}
