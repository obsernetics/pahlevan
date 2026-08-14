package export

// Filter decides which envelopes reach the sinks. The zero Filter passes
// everything.
type Filter struct {
	// Types selects the event types to export. Empty means every type.
	Types map[EventType]bool
	// DenialsOnly keeps only in-kernel denials. Exporting every observation is
	// noisy on a busy node; enforcement events are the interesting ones.
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
	if f.DenialsOnly && !e.Denied() {
		return false
	}
	return true
}
