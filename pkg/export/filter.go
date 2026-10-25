package export

// Filter decides which envelopes reach the sinks. The zero Filter passes
// everything.
type Filter struct {
	// Types selects the event types to export. Empty means every type.
	Types map[EventType]bool
	// DenialsOnly keeps in-kernel denials and events carrying a
	// post-exploitation signal. Exporting every observation is noisy on a busy
	// node; those two are the interesting ones.
	//
	// The signals are kept because the alternative is to publish nothing at
	// all on the configurations where they matter most. Enforcement needs the
	// BPF LSM, so on a kernel without it no event is ever a denial, and a
	// DenialsOnly stream is empty however hostile the node gets. A php-fpm
	// worker that just execed sh belongs in that stream.
	DenialsOnly bool
}

// NewFilter builds a Filter from user supplied type names. An empty or nil
// list selects every type.
func NewFilter(types []string, denialsOnly bool) (Filter, error) {
	f := Filter{DenialsOnly: denialsOnly}
	for _, name := range types {
		if name == "" {
			continue
		}
		t, err := ParseEventType(name)
		if err != nil {
			return Filter{}, err
		}
		if f.Types == nil {
			f.Types = make(map[EventType]bool, len(types))
		}
		f.Types[t] = true
	}
	return f, nil
}

// AllowType reports whether the type passes the type selection. It lets the
// adapter skip conversion work entirely for types nobody wants.
func (f Filter) AllowType(t EventType) bool {
	if len(f.Types) == 0 {
		return true
	}
	return f.Types[t]
}

// Allow reports whether an envelope passes the filter.
func (f Filter) Allow(e *Event) bool {
	if e == nil {
		return false
	}
	if !f.AllowType(e.Type) {
		return false
	}
	if f.DenialsOnly && !e.Denied() && !e.Signalled() {
		return false
	}
	return true
}
