// Command apidocs generates the CRD reference from the Go types.
//
// docs/api-reference.md was written by hand and described an API that does not
// exist. Not a field here and there: `learning:` instead of `learningConfig:`,
// `enforcement:` instead of `enforcementConfig:`, and whole subsystems -
// maxSamples, confidence, aggressive, emergencyMode, syscall argument filters,
// per-rule network directions - that the CRD has never had.
//
// It is the document called "API Reference". Somebody reading it to find out
// what they can configure was reading fiction, and every field they copied
// would have been pruned by the API server without an error.
//
// Hand-writing it again would produce the same outcome a year later, so it is
// generated from the types the API server actually serves. A test asserts the
// committed file matches what this produces, which is what stops the drift
// rather than merely correcting it once.
//
//	go run ./hack/apidocs > docs/api-reference.md
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
)

const typesFile = "pkg/apis/policy/v1alpha1/types.go"

// field is one JSON-visible field of a struct.
type field struct {
	JSON     string
	GoType   string
	Doc      string
	Optional bool
	// Enum holds the permitted values when the type carries a kubebuilder enum
	// marker, because "which values may I write here" is the question a
	// reference is most often opened to answer.
	Enum []string
}

type structDoc struct {
	Name   string
	Doc    string
	Fields []field
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, root+"/"+typesFile, nil, parser.ParseComments)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apidocs: %v\n", err)
		os.Exit(1)
	}

	structs := map[string]*structDoc{}
	consts := collectEnumValues(f)

	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			doc := gd.Doc
			if ts.Doc != nil {
				doc = ts.Doc
			}
			sd := &structDoc{Name: ts.Name.Name, Doc: cleanDoc(doc, ts.Name.Name)}
			for _, fl := range st.Fields.List {
				if fl.Tag == nil {
					continue
				}
				jsonName, optional := parseJSONTag(fl.Tag.Value)
				if jsonName == "" || jsonName == "-" {
					continue
				}
				goType := exprString(fl.Type)
				sd.Fields = append(sd.Fields, field{
					JSON:     jsonName,
					GoType:   goType,
					Doc:      cleanDoc(fl.Doc, ""),
					Optional: optional,
					Enum:     enumFor(fl, goType, consts),
				})
			}
			structs[sd.Name] = sd
		}
	}

	render(structs)
}

// enumFor returns the permitted values for a field, from an explicit
// kubebuilder marker if present and otherwise from the constants declared for
// its named type.
func enumFor(fl *ast.Field, goType string, consts map[string][]string) []string {
	if fl.Doc != nil {
		for _, c := range fl.Doc.List {
			if m := regexp.MustCompile(`\+kubebuilder:validation:Enum=(.+)$`).
				FindStringSubmatch(strings.TrimSpace(c.Text)); m != nil {
				return strings.Split(strings.TrimSpace(m[1]), ";")
			}
		}
	}
	base := strings.TrimPrefix(strings.TrimPrefix(goType, "[]"), "*")
	if v, ok := consts[base]; ok {
		return v
	}
	return nil
}

// collectEnumValues finds the string constants declared for each named type, so
// a field of type EnforcementMode documents Off/Monitoring/Blocking without an
// explicit marker.
func collectEnumValues(f *ast.File) map[string][]string {
	out := map[string][]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || vs.Type == nil || len(vs.Values) == 0 {
				continue
			}
			typeName := exprString(vs.Type)
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			out[typeName] = append(out[typeName], strings.Trim(lit.Value, `"`))
		}
	}
	return out
}

func parseJSONTag(tag string) (name string, optional bool) {
	m := regexp.MustCompile(`json:"([^"]*)"`).FindStringSubmatch(tag)
	if m == nil {
		return "", false
	}
	parts := strings.Split(m[1], ",")
	for _, p := range parts[1:] {
		if p == "omitempty" {
			optional = true
		}
	}
	return parts[0], optional
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.StarExpr:
		return "*" + exprString(v.X)
	case *ast.ArrayType:
		return "[]" + exprString(v.Elt)
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.MapType:
		return "map[" + exprString(v.Key) + "]" + exprString(v.Value)
	default:
		return "object"
	}
}

// cleanDoc turns a Go comment into one line of prose, dropping the leading type
// name and every kubebuilder marker.
func cleanDoc(g *ast.CommentGroup, stripPrefix string) string {
	if g == nil {
		return ""
	}
	var lines []string
	for _, c := range g.List {
		t := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(c.Text, "//"), "/*"))
		t = strings.TrimSuffix(t, "*/")
		t = strings.TrimSpace(t)
		if t == "" || strings.HasPrefix(t, "+") {
			continue
		}
		lines = append(lines, t)
	}
	doc := strings.Join(lines, " ")
	if stripPrefix != "" {
		doc = strings.TrimPrefix(doc, stripPrefix+" ")
	}
	// Markdown tables cannot contain an unescaped pipe.
	return strings.ReplaceAll(doc, "|", `\|`)
}

// roots are the types worth a section, in the order somebody reads them.
var roots = []string{
	"PahlevanPolicy", "PahlevanPolicySpec",
	"LearningConfig", "EnforcementConfig", "EnforcementException",
	"FilePolicy", "ExecutableFilter",
	"SyscallPolicy", "ProcessFilter",
	"NetworkPolicy", "NetworkRule", "NetworkPeer", "NetworkPort", "IPBlock",
	"SelfHealingConfig", "ObservabilityConfig",
	"PahlevanPolicyStatus", "LearningStatus", "EnforcementStatus",
	"ContainerProfile", "ContainerProfileSpec", "ContainerProfileStatus",
	"AttackSurface", "AttackSurfaceSpec", "AttackSurfaceStatus",
}

// inert names the fields the API accepts and the agent does not act on. They
// are documented rather than hidden, because a reader who finds one in a
// cluster needs to know what it does - and the answer is nothing.
var inert = map[string]string{
	"LearningConfig.windowSize":              "the controller observes continuously, not in sampling windows",
	"LearningConfig.lifecycleAware":          "stored and displayed; nothing acts on it",
	"FilePolicy.defaultAction":               "redundant: default-deny is what enforcement is",
	"SyscallPolicy.defaultAction":            "redundant: default-deny is what enforcement is",
	"NetworkPolicy.defaultAction":            "redundant: default-deny is what enforcement is",
	"ExecutableFilter.requireSignature":      "nothing verifies executable signatures",
	"PahlevanPolicySpec.observabilityConfig": "the agent's flags configure telemetry, per node rather than per policy",
}

func render(structs map[string]*structDoc) {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }

	p("# API reference")
	p("")
	p("<!-- Generated by hack/apidocs from pkg/apis/policy/v1alpha1/types.go. -->")
	p("<!-- Do not edit by hand: `go run ./hack/apidocs > docs/api-reference.md`. -->")
	p("")
	p("Every field below exists in the CRD the API server serves, because this")
	p("document is generated from the Go types rather than written alongside them.")
	p("")
	p("That matters more than it sounds. The previous version of this file was")
	p("hand-written and described an API that had never existed - `learning:`")
	p("instead of `learningConfig:`, `enforcement:` instead of")
	p("`enforcementConfig:`, plus whole subsystems the CRD has never had. A")
	p("Kubernetes API server does not reject an unknown field in a custom")
	p("resource; it prunes it. So anyone who copied from it got a policy that")
	p("applied cleanly and did a fraction of what they asked for, with no error")
	p("anywhere.")
	p("")
	p("Fields marked **inert** are accepted by the API and acted on by nothing.")
	p("They are listed rather than hidden, because finding one in a cluster and")
	p("not knowing is worse than being told. `pahlevan policy explain -f` names")
	p("every one in a given policy.")
	p("")

	for _, name := range roots {
		sd, ok := structs[name]
		if !ok {
			continue
		}
		p("## %s", name)
		p("")
		if sd.Doc != "" {
			p("%s", sd.Doc)
			p("")
		}
		if len(sd.Fields) == 0 {
			p("_No fields._")
			p("")
			continue
		}
		p("| Field | Type | Required | Description |")
		p("|---|---|:---:|---|")
		for _, fl := range sd.Fields {
			req := "yes"
			if fl.Optional {
				req = ""
			}
			desc := fl.Doc
			if len(fl.Enum) > 0 {
				desc = strings.TrimSpace(desc + " One of: `" +
					strings.Join(fl.Enum, "`, `") + "`.")
			}
			if why, dead := inert[name+"."+fl.JSON]; dead {
				desc = "**Inert** - " + why + ". " + desc
			}
			p("| `%s` | `%s` | %s | %s |", fl.JSON, fl.GoType, req, strings.TrimSpace(desc))
		}
		p("")
	}

	// Anything reachable but not in roots, so a new type cannot be silently
	// left undocumented.
	var rest []string
	inRoots := map[string]bool{}
	for _, r := range roots {
		inRoots[r] = true
	}
	for name := range structs {
		if !inRoots[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	if len(rest) > 0 {
		p("## Other types")
		p("")
		p("Reachable from the types above; listed so a new one cannot go")
		p("undocumented by omission.")
		p("")
		for _, name := range rest {
			p("- `%s`", name)
		}
		p("")
	}

	fmt.Print(b.String())
}
