package dashboard

import (
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// These tests parse the bytes the server actually writes, not a constant in
// the source. A policy that forbids inline script and a page that contains
// none are two separate claims, and only the second one is about what a
// browser receives.

// element is one parsed tag: its name, its attributes and the text directly
// inside it.
type element struct {
	name  string
	attrs map[string]string
	text  string
}

// parseMarkup tokenises HTML or SVG.
//
// encoding/xml in non-strict mode with the HTML auto-close and entity tables
// is the standard library's own answer for HTML-shaped input. It is a real
// tokeniser: it sees elements and attributes, so "is there a script element
// with code in it" is answered by the parse rather than by a regular
// expression that a differently spelled tag would slip past.
func parseMarkup(t *testing.T, body string) []element {
	t.Helper()
	decoder := xml.NewDecoder(strings.NewReader(body))
	decoder.Strict = false
	decoder.AutoClose = xml.HTMLAutoClose
	decoder.Entity = xml.HTMLEntity

	var out []element
	var stack []int
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("parsing the served markup: %v", err)
		}
		switch tok := token.(type) {
		case xml.StartElement:
			e := element{name: strings.ToLower(tok.Name.Local), attrs: map[string]string{}}
			for _, a := range tok.Attr {
				e.attrs[strings.ToLower(a.Name.Local)] = a.Value
			}
			out = append(out, e)
			stack = append(stack, len(out)-1)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				out[stack[len(stack)-1]].text += string(tok)
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("the served markup parsed to no elements at all")
	}
	return out
}

func fetchAsset(t *testing.T, server *Server, path string) string {
	t.Helper()
	rec := get(t, server, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", path, rec.Code)
	}
	return rec.Body.String()
}

func testServerForAssets(t *testing.T) *Server {
	t.Helper()
	return newTestServer(t, newFakeAuth(true, allowNamespaces(visibleNS)), nil)
}

// An inline script cannot run under this policy, so one in the page is a page
// that silently does not work - or, worse, the reason somebody weakens the
// policy for everybody.
func TestServedHTMLHasNoInlineScript(t *testing.T) {
	server := testServerForAssets(t)
	body := fetchAsset(t, server, "/")

	scripts := 0
	for _, e := range parseMarkup(t, body) {
		if e.name != "script" {
			continue
		}
		scripts++
		if strings.TrimSpace(e.text) != "" {
			t.Fatalf("a script element carries inline code: %q", strings.TrimSpace(e.text))
		}
		if e.attrs["src"] == "" {
			t.Fatal("a script element has neither a src nor inline code")
		}
	}
	if scripts == 0 {
		t.Fatal("the page loads no script at all, so this test would pass on an empty file")
	}
}

func TestServedHTMLHasNoInlineStyleOrEventHandlers(t *testing.T) {
	server := testServerForAssets(t)

	for _, e := range parseMarkup(t, fetchAsset(t, server, "/")) {
		if e.name == "style" {
			t.Fatal("the page carries a style element, which style-src 'self' will not apply")
		}
		for name := range e.attrs {
			if name == "style" {
				t.Fatalf("<%s> carries a style attribute, which the policy blocks", e.name)
			}
			// An inline handler is script by another name; the policy blocks
			// it, and it is the attribute an injected value most easily lands
			// in.
			if strings.HasPrefix(name, "on") && name != "only" {
				t.Fatalf("<%s> carries the inline handler %q", e.name, name)
			}
		}
	}
}

// externalRef matches anything that would make a browser talk to another
// origin: an absolute URL, or a protocol-relative one.
var externalRef = regexp.MustCompile(`(?i)(https?:)?//[a-z0-9.-]+`)

func TestNoServedAssetReferencesAnExternalOrigin(t *testing.T) {
	server := testServerForAssets(t)

	// Prove the detector detects, so a regular expression that stopped
	// matching cannot turn this whole test into a pass.
	for _, sample := range []string{
		`<script src="https://cdn.example.com/chart.js"></script>`,
		`@import url(//fonts.example.com/x.css);`,
		`fetch("http://metrics.example.com/beacon")`,
	} {
		if externalRef.FindString(sample) == "" {
			t.Fatalf("the external-origin detector does not match %q", sample)
		}
	}

	// Every embedded file, fetched through the server, so what is checked is
	// what is served.
	for _, name := range AssetNames() {
		t.Run(name, func(t *testing.T) {
			body := fetchAsset(t, server, "/"+name)
			for _, line := range strings.Split(body, "\n") {
				// A comment saying the word "https" is not a reference; a
				// javascript-protocol URL and a scheme-ful src are.
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") ||
					strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "<!--") {
					continue
				}
				if match := externalRef.FindString(line); match != "" {
					t.Fatalf("%s reaches an external origin: %q in %q", name, match, trimmed)
				}
			}
		})
	}
}

func TestHTMLReferencesOnlyAssetsThatExist(t *testing.T) {
	// A stylesheet that 404s is a page that renders as unstyled text, and it
	// is the kind of thing a rename breaks silently.
	server := testServerForAssets(t)
	referenced := 0
	for _, e := range parseMarkup(t, fetchAsset(t, server, "/")) {
		for _, attr := range []string{"src", "href"} {
			ref := e.attrs[attr]
			if ref == "" || strings.HasPrefix(ref, "#") {
				continue
			}
			referenced++
			if strings.HasPrefix(ref, "/") {
				t.Fatalf("<%s %s=%q> is root-relative; the assets are served next to the page", e.name, attr, ref)
			}
			if _, ok := Asset(ref); !ok {
				t.Fatalf("<%s %s=%q> names a file the binary does not carry", e.name, attr, ref)
			}
		}
	}
	if referenced < 2 {
		t.Fatalf("the page referenced %d assets, want at least the stylesheet and the script", referenced)
	}
}

func TestCSSLoadsNothingRemote(t *testing.T) {
	server := testServerForAssets(t)
	css := fetchAsset(t, server, "/app.css")

	for _, forbidden := range []string{"@import", "url(http", "url(//", "@font-face"} {
		if strings.Contains(css, forbidden) {
			t.Fatalf("app.css contains %q, which fetches from somewhere the policy does not allow", forbidden)
		}
	}
	// The diagram classes are the contract with svg.go. A renamed class there
	// produces an unstyled, unreadable diagram, which no other test notices.
	for _, class := range []string{
		".flow-box", ".flow-arrow", ".bar-track", ".bar-fill", ".tree-line", ".tree-label", ".tree-denied",
	} {
		if !strings.Contains(css, class) {
			t.Fatalf("app.css has no rule for %s, which pkg/dashboard/svg.go emits", class)
		}
	}
}

func TestJavaScriptUsesNoDynamicEvaluation(t *testing.T) {
	server := testServerForAssets(t)
	js := fetchAsset(t, server, "/app.js")

	for _, forbidden := range []string{"eval(", "new Function(", "document.write", "importScripts("} {
		if strings.Contains(js, forbidden) {
			t.Fatalf("app.js uses %q, which script-src without 'unsafe-eval' blocks", forbidden)
		}
	}
	// Data from the cluster is a container's command line and its file paths.
	// It goes into the document as text, never as markup.
	if strings.Contains(js, ".innerHTML") || strings.Contains(js, ".outerHTML") {
		t.Fatal("app.js assigns HTML from a string, so a hostile path or command name would be parsed as markup")
	}
	if !strings.Contains(js, "Authorization") {
		t.Fatal("app.js never sets an Authorization header, so it cannot be authenticating at all")
	}
	if strings.Contains(js, "document.cookie") {
		t.Fatal("app.js touches cookies; the token belongs in a header the page sets deliberately")
	}
}

func TestAssetsAreServedWithTheRightType(t *testing.T) {
	// Under nosniff, JavaScript served as text/plain does not run, and the
	// symptom is a blank page with a console message nobody connects to the
	// header.
	server := testServerForAssets(t)
	for path, want := range map[string]string{
		"/":         "text/html; charset=utf-8",
		"/app.css":  "text/css; charset=utf-8",
		"/app.js":   "text/javascript; charset=utf-8",
		"/nonesuch": "application/json; charset=utf-8",
	} {
		rec := get(t, server, path)
		if got := rec.Header().Get("Content-Type"); got != want {
			t.Fatalf("GET %s had content type %q, want %q", path, got, want)
		}
	}
}

func TestAssetLookupRefusesTraversal(t *testing.T) {
	// The allowlist cannot be talked into leaving the embedded tree, whatever
	// the path spells.
	for _, name := range []string{
		"../store.go", "../../go.mod", "/etc/passwd", "assets/index.html", "..%2fstore.go",
	} {
		if _, ok := Asset(name); ok {
			t.Fatalf("Asset(%q) resolved to a file", name)
		}
	}
	if _, ok := Asset(IndexPath); !ok {
		t.Fatalf("Asset(%q) found nothing, so the allowlist is empty and the test above is vacuous", IndexPath)
	}

	server := testServerForAssets(t)
	for _, path := range []string{"/../store.go", "/assets/index.html", "/%2e%2e/go.mod"} {
		if rec := get(t, server, path); rec.Code == http.StatusOK {
			t.Fatalf("GET %s served a file: %s", path, rec.Body.String())
		}
	}
}

func TestEmbeddedAssetsArePresent(t *testing.T) {
	want := map[string]bool{"index.html": false, "app.css": false, "app.js": false}
	for _, name := range AssetNames() {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("the binary does not carry %s, so the dashboard would serve a 404 for it", name)
		}
	}
}
