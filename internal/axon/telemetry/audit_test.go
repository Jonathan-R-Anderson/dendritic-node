// Package telemetry carries T16.3's audit: what a node may say about itself.
//
// It is a test-only package, like internal/axon/storage. There is nothing to
// build — the property is about what the EXISTING telemetry types are allowed to
// contain, and no runtime test of a working monitor establishes that.
//
// T16.3: "Metrics contain no per-circuit, per-name or per-peer identifier, by
// schema audit."
//
// §23's P16 card names the failure mode precisely: "monitoring that is useful
// precisely because it is deanonymising". The useful field and the dangerous
// field are the same field — which circuit was slow, which name failed to
// resolve, which peer timed out — so this cannot be left to judgement at the
// call site. It has to be a rule about the schema.
//
// WHAT IS ALLOWED. Aggregate counts and this node's own identity: how many
// objects, how many peers, how many placements failed, how long a probe took,
// and who is reporting. A node signs its reports, so its own id is attribution
// rather than surveillance, and removing it would make the reports unverifiable.
//
// WHAT IS NOT. Anything that names a THIRD PARTY or a UNIT OF WORK: a circuit
// id, a resolved name, an object or shard id, another peer's identity, an
// address. Each of those turns a health metric into a record of who did what.
package telemetry

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// transmitting is the set of packages whose types actually leave the node.
//
// Listed rather than discovered, and that is the one manual step here: a struct
// with json tags is not necessarily transmitted, and auditing every one of them
// would flag the config file and the on-disk ledger. What must not happen is a
// new transmitting package being added and not listed, so TestEveryTransmitter
// IsAudited checks the list against the code that posts.
var transmitting = []string{
	"internal/monitor",
	"internal/heartbeat",
}

// Field names that name a third party or a unit of work.
var forbidden = regexp.MustCompile(`(?i)^(` +
	`circuit\w*|circ_?id|` +
	`stream_?id|` +
	`name|domain|hostname|fqdn|zone|` +
	`object_?id|shard_?id|cid|manifest|` +
	`peer_?id|remote_?id|node_?ids|` +
	`addr|address|ip|endpoint|destination|multiaddr|` +
	`key_?hash|namehash` +
	`)$`)

// Names that look dangerous and are not, with the reason each is allowed.
var allowed = map[string]string{
	// The reporting node's OWN id. Reports are signed with it; removing it makes
	// them unverifiable, and it identifies the reporter rather than a subject.
	"NodeID": "the reporting node's own identity, which its signature already binds",
	// A probe target's short key ("gateway", "dht") — a component name, not a
	// name anybody resolved.
	"Key": "a component key such as \"gateway\", not a resolved name",
	// The human label of a probe target, from the site's own target list.
	"Name": "a probe target's label, supplied by the site rather than observed",
	// A probe target's URL, likewise from the site's own list.
	"URL":       "a probe target supplied by the site, not a destination a user chose",
	"ReportURL": "where to post, supplied by the site",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..")
}

// TestT163NoTelemetryFieldNamesAThirdParty is T16.3.
func TestT163NoTelemetryFieldNamesAThirdParty(t *testing.T) {
	fset := token.NewFileSet()
	checked := 0

	for _, pkg := range transmitting {
		dir := filepath.Join(repoRoot(t), pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", pkg, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				st, ok := n.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range st.Fields.List {
					// Only fields that are SERIALISED. An unexported or
					// untagged field stays inside the process.
					if field.Tag == nil || !strings.Contains(field.Tag.Value, `json:"`) {
						continue
					}
					for _, name := range field.Names {
						checked++
						if !name.IsExported() {
							continue
						}
						if _, ok := allowed[name.Name]; ok {
							continue
						}
						if forbidden.MatchString(name.Name) {
							t.Errorf("T16.3 violated: %s has a transmitted field %q. "+
								"Metrics may carry aggregate counts and this node's own "+
								"identity; a field naming a third party or a unit of work "+
								"turns monitoring into a record of who did what.",
								filepath.Join(pkg, e.Name()), name.Name)
						}
					}
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("no transmitted fields were examined; the audit is looking in the wrong place")
	}
	t.Logf("T16.3: %d transmitted fields checked across %d packages", checked, len(transmitting))
}

// TestEveryTransmitterIsAudited stops the list above from going stale.
//
// The audit is only as good as its scope. A new package that posts telemetry and
// is not in `transmitting` is unaudited, and nothing would say so — which is the
// same silent-gap shape as the metrics leak itself.
func TestEveryTransmitterIsAudited(t *testing.T) {
	posts := regexp.MustCompile(`http\.(Post|NewRequest)\(`)
	root := filepath.Join(repoRoot(t), "internal")

	var unaudited []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		body := string(src)
		// Posts somewhere AND declares a json-tagged struct: that is the shape
		// of a telemetry sender.
		if !posts.MatchString(body) || !strings.Contains(body, `json:"`) {
			return nil
		}
		rel := filepath.ToSlash(filepath.Dir(path))
		i := strings.Index(rel, "internal/")
		if i < 0 {
			return nil
		}
		rel = rel[i:]
		for _, known := range transmitting {
			if rel == known {
				return nil
			}
		}
		// Not everything that posts is telemetry -- a payment client posts too.
		// Reported rather than failed, so the list is reviewed rather than
		// grown reflexively.
		unaudited = append(unaudited, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	seen := map[string]bool{}
	var uniq []string
	for _, u := range unaudited {
		if !seen[u] {
			seen[u] = true
			uniq = append(uniq, u)
		}
	}
	if len(uniq) > 0 {
		t.Logf("packages that POST json and are not in the T16.3 audit list — "+
			"review each and either add it to `transmitting` or note why it is "+
			"not telemetry:\n  %s", strings.Join(uniq, "\n  "))
	}
}

// TestFreeTextFieldsAreBounded covers the field a schema audit cannot see into.
//
// `Detail string` is the escape hatch: it passes every name check and can carry
// anything the code decides to put in it. A schema rule cannot police its
// CONTENTS, so the rule is about its SIZE — a detail long enough to hold a
// multiaddr or a manifest CID is long enough to be worth reviewing.
func TestFreeTextFieldsAreBounded(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "monitor", "monitor.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if !strings.Contains(body, "Detail") {
		t.Skip("no Detail field to bound")
	}
	// Now an assertion, not a note. The first run of this audit reported Detail
	// as unbounded free text; monitor.sanitiseDetail was added in response, so
	// the property is real and must stay.
	if !strings.Contains(body, "sanitiseDetail(") {
		t.Error("T16.3: monitor's Detail is assigned without sanitiseDetail. Go's " +
			"HTTP errors carry the RESOLVED ADDRESS of the target -- " +
			`Get "https://x": dial tcp 203.0.113.9:443: connection refused` +
			" -- and a schema audit checks field names, so it cannot see this.")
	}
	for _, want := range []string{"maxDetail", "ipInError"} {
		if !strings.Contains(body, want) {
			t.Errorf("T16.3: monitor no longer bounds Detail (%s is gone)", want)
		}
	}
	// Every assignment must go through it, not just the first one.
	for i, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "result.Detail =") {
			continue
		}
		if !strings.Contains(trimmed, "sanitiseDetail(") {
			t.Errorf("monitor.go:%d assigns Detail without sanitising:\n\t%s", i+1, trimmed)
		}
	}
}
