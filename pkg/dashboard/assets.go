package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"
)

// The whole front end, compiled into the binary.
//
// Serving from embed rather than from a directory is not a packaging
// convenience, it is the Content-Security-Policy made true: "no external
// origin" is only a real statement if there is no origin for the page to reach
// for, and a dashboard image with no CDN dependency also has no CDN outage, no
// third-party supply chain, and nothing for an air-gapped cluster to mirror.
//
//go:embed assets
var assetFS embed.FS

// IndexPath is the file served for the root of the site.
const IndexPath = "index.html"

// assetNames is the set of files that may be served, built once from the
// embedded tree.
//
// An allowlist rather than cleaning the request path, because path traversal
// bugs are a family of mistakes rather than one mistake: every one of them is
// some string that survives normalisation and means "the parent directory".
// A lookup in a fixed set cannot be talked into anything.
var assetNames = buildAssetNames()

func buildAssetNames() map[string]struct{} {
	names := map[string]struct{}{}
	_ = fs.WalkDir(assetFS, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		names[strings.TrimPrefix(p, "assets/")] = struct{}{}
		return nil
	})
	return names
}

// AssetNames lists the embedded files, sorted. Tests use it to assert what the
// binary actually serves rather than what a list somewhere claims.
func AssetNames() []string {
	out := make([]string, 0, len(assetNames))
	for n := range assetNames {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Asset returns one embedded file.
func Asset(name string) ([]byte, bool) {
	if _, ok := assetNames[name]; !ok {
		return nil, false
	}
	data, err := assetFS.ReadFile("assets/" + name)
	if err != nil {
		return nil, false
	}
	return data, true
}

// assets serves the embedded front end.
func (s *Server) assets() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || name == "." {
			name = IndexPath
		}
		data, ok := Asset(name)
		if !ok {
			// A 404 in JSON, matching every other failure the page can hit, so
			// the client's error handling has one shape rather than two.
			writeError(w, http.StatusNotFound, "no such page; the dashboard serves "+IndexPath+" and its assets")
			return
		}
		w.Header().Set("Content-Type", contentTypeFor(name))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}
