package padding

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRel walks up to the module root and lists Go files under a subtree.
func repoFiles(t *testing.T, rel string) []string {
	t.Helper()
	root := filepath.Join("..", "..", "..", rel)
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", rel, err)
	}
	if len(out) == 0 {
		t.Fatalf("no Go files under %s -- the audit is looking in the wrong place", rel)
	}
	return out
}

// TestE134EveryPaddingParameterAppearsOnce is E13.4.
//
// §16.8's last row makes ONE CANONICAL WIRE PROFILE normative. A second
// definition of any padding figure is a second profile, and configuration
// diversity is itself the node fingerprint the canonical profile exists to
// remove — so this is not a style rule, it is the mechanism.
//
// The check is for a literal appearing outside params, not for the constant
// being referenced: a duplicate is written as a number, never as a reference.
func TestE134EveryPaddingParameterAppearsOnce(t *testing.T) {
	// The value, and a pattern that matches it written as a literal.
	literals := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"DatagramSize (1200)", regexp.MustCompile(`\b1200\b`)},
		{"KeepaliveMin (1500ms)", regexp.MustCompile(`\b1500\s*\*\s*time\.Millisecond\b`)},
		{"KeepaliveMax (9500ms)", regexp.MustCompile(`\b9500\s*\*\s*time\.Millisecond\b`)},
		{"FloorRateCellsPerSec (0.5)", regexp.MustCompile(`FloorRate\s*=\s*0\.5`)},
		{"FloorTailMin (5s)", regexp.MustCompile(`FloorTail\w*\s*=\s*5\s*\*\s*time\.Second`)},
		{"FloorTailMax (30s)", regexp.MustCompile(`FloorTail\w*\s*=\s*30\s*\*\s*time\.Second`)},
		{"RotationJitter (0.15)", regexp.MustCompile(`Jitter\s*=\s*0\.15`)},
	}

	for _, path := range repoFiles(t, "internal/axon") {
		if strings.HasSuffix(path, "_test.go") {
			// Tests state expected values on purpose -- that is what makes them
			// tests. A test cannot change the wire profile.
			continue
		}
		if strings.Contains(filepath.ToSlash(path), "/axon/params/") {
			continue // the one legitimate home
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			// A comment quoting §16.3's figure is documentation, not a second
			// definition -- and forbidding it would push the derivation out of
			// the code, which is the opposite of what E13.4 is for.
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			for _, lit := range literals {
				if lit.pattern.MatchString(line) {
					t.Errorf("E13.4 violated: %s:%d redefines %s outside params:\n\t%s",
						path, i+1, lit.name, strings.TrimSpace(line))
				}
			}
		}
	}
}

// TestT132NoOperatorKnobChangesAPreHandshakeByte is T13.2.
//
// §16.8: one canonical wire profile, no tunable knobs on the wire. The audit
// looks for the shape a knob actually takes in Go — a struct field, a flag, or
// an environment read — anywhere in the code that produces bytes before the
// handshake completes: the transport parameters, the cell framing, and the
// padding schedule.
//
// What it CANNOT establish is stated rather than implied: it does not see
// through quic-go, which owns the QUIC Initial itself. That is T13.1's
// territory and T13.1 is not discharged; see the P13 note in the roadmap.
func TestT132NoOperatorKnobChangesAPreHandshakeByte(t *testing.T) {
	env := regexp.MustCompile(`os\.(Getenv|LookupEnv)`)
	flags := regexp.MustCompile(`flag\.(String|Int|Bool|Duration|Float64)`)

	for _, path := range repoFiles(t, "internal/axon") {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		p := filepath.ToSlash(path)
		preHandshake := strings.Contains(p, "/axon/link/") ||
			strings.Contains(p, "/axon/padding/") ||
			strings.Contains(p, "/axon/params/")
		if !preHandshake {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if loc := env.FindIndex(src); loc != nil {
			line := 1 + strings.Count(string(src[:loc[0]]), "\n")
			t.Errorf("T13.2 violated: %s:%d reads the environment on the pre-handshake path", path, line)
		}
		if loc := flags.FindIndex(src); loc != nil {
			line := 1 + strings.Count(string(src[:loc[0]]), "\n")
			t.Errorf("T13.2 violated: %s:%d defines a command-line flag on the pre-handshake path", path, line)
		}
	}
}

// TestT133PaddingIsNotATunable is the other half of T13.3.
//
// The failure mode §23 names is precise: "padding that costs bandwidth without
// measurable benefit, which volunteers disable, which makes NOT padding the
// fingerprint". A rate knob is worse than an on/off switch, because it
// partitions operators into as many populations as there are settings. So the
// package must expose a bool and nothing resembling a rate.
func TestT133PaddingIsNotATunable(t *testing.T) {
	tunable := regexp.MustCompile(`func .*Set(Rate|Interval|Floor|Keepalive|Padding\w*Rate)\(`)
	for _, path := range repoFiles(t, "internal/axon/padding") {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if m := tunable.FindString(string(src)); m != "" {
			t.Errorf("T13.3 violated: %s exposes a padding tunable: %s", path, m)
		}
	}
}

// TestPaddingScheduleDoesNotDependOnTrafficClass is P13's subtlest requirement.
//
// R2 separates INTERACTIVE from BULK. If the PADDING rate differed by class,
// the class would be inferable from the padding — which hands back the very
// distinction the classes were separated to bound, and does it on the link an
// access-link observer already watches.
//
// The audit is structural: nothing in this package may reference a traffic
// class at all, so a class-dependent schedule is not expressible.
func TestPaddingScheduleDoesNotDependOnTrafficClass(t *testing.T) {
	class := regexp.MustCompile(`(?i)\b(interactive|bulk|trafficclass|priority)\b`)
	for _, path := range repoFiles(t, "internal/axon/padding") {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !class.MatchString(line) {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue // the doc comment explains exactly this rule
			}
			t.Errorf("%s:%d makes the padding schedule aware of a traffic class:\n\t%s",
				path, i+1, strings.TrimSpace(line))
		}
	}
}
