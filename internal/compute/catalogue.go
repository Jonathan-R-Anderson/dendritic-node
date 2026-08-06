package compute

// M10 slice 1 — the workload catalogue: what a node will run that is NOT a
// language runtime.
//
// WHY THIS TABLE EXISTS SEPARATELY FROM THE LANGUAGE TABLE
// --------------------------------------------------------
// The language images (python, go, c) execute a program the submitter wrote.
// They are gated on M2 for exactly that reason, and every one of them is a
// promise the node cannot keep until a microVM is under it.
//
// A catalogue workload is the opposite shape: the CODE is fixed at image-build
// time and the submitter supplies only DATA. That is what makes it deployable
// today under the catalogue rule rather than after arbitrary-code execution is
// defensible — and it is why widening this table is not, and must never become,
// a way of relaxing the arbitrary-code boundary. A workload entry names an image
// the operator's node already trusts; it never carries a program.
//
// THE CLOSED-TABLE PROPERTY
// -------------------------
// A name that is not in this map is REFUSED. It is never forwarded as an image
// string, never concatenated into a reference, never defaulted to. That single
// rule is what keeps "submitter picks the workload" from meaning "submitter
// picks the image", which is the same escape the language table is closed
// against. Everything else here is bookkeeping; that is the security property.

import (
	"errors"
	"strings"
)

// Workload is one entry in the catalogue: an image the node may run, plus what
// the rest of the system needs to know about it without opening the image.
type Workload struct {
	// Name is what a submitter asks for. The map key too — duplicated into the
	// value so a Workload passed around alone can still say what it is.
	Name string

	// Image is the pinned reference this workload runs. Set HERE and nowhere
	// else: the node reads it from this table after matching a name, so there is
	// no path from a request to an arbitrary image.
	Image string

	// Class is what this work IS — media, index, train, infer, science. It is
	// what an operator's JobClasses allowlist filters on and what the "what has
	// my machine been doing" history is written from, so it belongs to the
	// workload rather than to the request.
	Class string

	// Deterministic declares that two correct executions produce identical
	// bytes. It decides which M5 instrument applies — hash equality or
	// median-anchored tolerance — so it is a property of the image, established
	// when the image is admitted to the catalogue, never a claim by the caller.
	Deterministic bool

	// InputFile is the name the image expects its data under, relative to the
	// job's working directory ("input.jsonl"). The image does not take a path
	// argument; a submitter who could name the file could name /etc/passwd.
	InputFile string

	// OutputFile is the name the image writes its PRODUCT under, relative to
	// the same working directory ("output.jsonl"). Relative for the same reason
	// InputFile is, and declared here for a reason InputFile does not have: the
	// node is what reaches into the container and fetches it back out, and a
	// file it was never told to fetch is destroyed with the container moments
	// later.
	//
	// This field's absence was a real defect, not a missing convenience. A
	// workload with nowhere to name its output had its result collected by
	// nobody, so an embedding job returned its stdout digest, exit 0, and no
	// vectors — a silent success that the site verified by hash and paid for.
	//
	// Mirrors `output_file` in backend/services/compute_catalogue.py, which
	// already carried it; backend/tests/test_compute_catalogue.py reads both
	// tables and fails when they disagree.
	OutputFile string

	// NeedsEntrypoint is true for images that run a submitted program and false
	// for data-only workloads. Data-only is the only kind in the table today,
	// and the field exists so that stays a visible fact rather than an
	// assumption baked into the dispatcher.
	NeedsEntrypoint bool

	// DefaultDeadline is the ceiling in seconds when the caller names none. A
	// unit without a deadline can occupy a volunteer's machine forever, so every
	// workload carries a sane one rather than relying on the submitter.
	DefaultDeadline int
}

// Workloads is the catalogue. One entry: M10's first slice.
//
// Deliberately small. A workload gets in only when there is an answer to "how is
// a returned result checked" — embed has one (bit-exact hash equality over a
// deterministic vector file, see compute-images/embed/embed.py), and workloads
// whose results cannot be checked stay out however useful they would be.
var Workloads = map[string]Workload{
	"embed": {
		Name:            "embed",
		Image:           "registry.local/compute-embed:latest",
		Class:           "index",
		Deterministic:   true,
		InputFile:       "input.jsonl",
		OutputFile:      "output.jsonl",
		NeedsEntrypoint: false,
		DefaultDeadline: 600,
	},
}

// ErrUnknownWorkload is returned rather than a formatted string so a caller can
// tell "you asked for something that does not exist" from "something went
// wrong", and answer the first with a 400 and the second with a 503.
var ErrUnknownWorkload = errors.New("compute: not a catalogue workload")

// LookupWorkload resolves a submitted name.
//
// The ONLY way to get a Workload from a name. Callers must not index Workloads
// directly, because a missing key yields a zero Workload whose Image is "" —
// which would be silently forwarded as "run the empty image" instead of being
// refused.
func LookupWorkload(name string) (Workload, bool) {
	w, ok := Workloads[strings.TrimSpace(name)]
	return w, ok
}

// IsCatalogueRuntime reports whether a string is the pinned reference of a
// registered workload.
//
// This is what lets Unit.Validate accept a tag reference without accepting
// image names in general: the only non-digest runtimes that pass are the exact
// strings in this file. "ubuntu:latest" is still refused, which is the property
// the digest rule was protecting.
func IsCatalogueRuntime(reference string) bool {
	for _, w := range Workloads {
		if w.Image != "" && w.Image == reference {
			return true
		}
	}
	return false
}

// UnitFor builds the M4 work unit for a catalogue workload.
//
// The unit is the request's canonical identity: its Digest() is what the node
// hands back as a ticket, and two submissions of the same work are therefore the
// same fact rather than two. That is the idempotence property M4 exists for, and
// it only holds if the unit is built HERE — from the table — rather than from
// anything the submitter sent.
//
// Note what is not a parameter: the image, the class and the determinism flag.
// Those come from the workload. A caller who could pass them could describe
// non-deterministic work as deterministic and have M5 verify it by hash
// equality, which would fail every honest replica.
func UnitFor(w Workload, device string, params map[string]string, seed int64, deadlineSeconds int) (Unit, error) {
	// A zero Workload means the caller skipped LookupWorkload. Refused rather
	// than run, because its Image is the empty string and "" is not a thing to
	// execute.
	if strings.TrimSpace(w.Name) == "" || strings.TrimSpace(w.Image) == "" {
		return Unit{}, ErrUnknownWorkload
	}
	if strings.TrimSpace(device) == "" {
		// The overwhelmingly common case, and the safe one: CPU work needs no
		// passthrough and no vendor driver. Defaulted rather than rejected so a
		// caller that omits the field gets the conservative device, not an error
		// about a field they did not know existed.
		device = "cpu"
	}
	if deadlineSeconds <= 0 {
		deadlineSeconds = w.DefaultDeadline
	}

	// Params are COPIED. The unit's digest is its identity, so a map the caller
	// still holds a reference to could be mutated after the digest was taken and
	// the unit would no longer be what it hashed as.
	var copied map[string]string
	if len(params) > 0 {
		copied = make(map[string]string, len(params))
		for k, v := range params {
			copied[k] = v
		}
	}

	unit := Unit{
		Runtime:         w.Image,
		Needs:           device,
		Class:           w.Class,
		Deterministic:   w.Deterministic,
		Seed:            seed,
		DeadlineSeconds: deadlineSeconds,
		Params:          copied,
	}
	if err := unit.Validate(); err != nil {
		return Unit{}, err
	}
	return unit, nil
}
