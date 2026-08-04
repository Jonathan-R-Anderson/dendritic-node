package computeworker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
	"github.com/syndichan/maniwani/storage-client/internal/dcs"
)

type fakeRuntime struct {
	mu       sync.Mutex
	created  []dcs.ContainerSpec
	removed  []string
	exitCode int
	stdout   string
	stderr   string
	startErr error
	waitFor  time.Duration
}

func (f *fakeRuntime) Create(_ context.Context, spec dcs.ContainerSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, spec)
	return "c-" + spec.Name, nil
}
func (f *fakeRuntime) Start(_ context.Context, _ string) error { return f.startErr }
func (f *fakeRuntime) Wait(ctx context.Context, _ string) (int, error) {
	if f.waitFor > 0 {
		select {
		case <-time.After(f.waitFor):
		case <-ctx.Done():
			return -1, ctx.Err()
		}
	}
	return f.exitCode, nil
}
func (f *fakeRuntime) Logs(_ context.Context, _ string) ([]byte, []byte, error) {
	return []byte(f.stdout), []byte(f.stderr), nil
}
func (f *fakeRuntime) Remove(_ context.Context, id string, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, id)
	return nil
}

func cpuPolicy() compute.Policy {
	return compute.Policy{Enabled: true, OfferCPU: true}
}

func job(device string) Job {
	return Job{ID: "job1", Device: device, Image: "img@sha256:abc", Timeout: 2 * time.Second}
}

// The operator's switch is a permanent no, and the caller must be able to tell.
// A queue that retries a permanent refusal forever never drains and never says
// why.
func TestDeclinedDeviceIsANonRetryableRefusal(t *testing.T) {
	w := New(&fakeRuntime{}, nil, cpuPolicy())
	err := w.Admit("gpu:cuda")
	if err == nil {
		t.Fatal("admitted GPU work the operator did not offer")
	}
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("got %T, want *Refusal", err)
	}
	if refusal.Retryable {
		t.Error("a declined device was reported as retryable")
	}
	if !strings.Contains(refusal.Reason, "gpu:cuda") {
		t.Errorf("reason %q does not name the device", refusal.Reason)
	}
}

func TestComputeOffIsRefused(t *testing.T) {
	w := New(&fakeRuntime{}, nil, compute.Policy{Enabled: false, OfferCPU: true})
	if err := w.Admit("cpu"); err == nil {
		t.Fatal("admitted work with compute disabled")
	}
}

func TestOfferedDeviceIsAdmitted(t *testing.T) {
	w := New(&fakeRuntime{}, nil, cpuPolicy())
	if err := w.Admit("cpu"); err != nil {
		t.Fatalf("refused offered CPU work: %v", err)
	}
}

// One job at a time per device, and the second must be told it is busy rather
// than silently queued or run alongside.
func TestSecondJobOnTheSameDeviceIsRefusedWhileBusy(t *testing.T) {
	rt := &fakeRuntime{waitFor: 400 * time.Millisecond}
	w := New(rt, nil, cpuPolicy())

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		_, _ = w.Run(context.Background(), job("cpu"))
		close(done)
	}()
	<-started
	time.Sleep(80 * time.Millisecond)

	err := w.Admit("cpu")
	if err == nil {
		t.Fatal("admitted a second job while one was running")
	}
	var refusal *Refusal
	if errors.As(err, &refusal) && !refusal.Retryable {
		t.Error("a busy slot should be retryable — it clears on its own")
	}
	<-done

	// And the slot must free afterwards, or the node accepts one job ever.
	if err := w.Admit("cpu"); err != nil {
		t.Errorf("slot did not free after the job finished: %v", err)
	}
}

func TestSuccessfulRunReturnsOutput(t *testing.T) {
	rt := &fakeRuntime{exitCode: 0, stdout: "hello\n", stderr: ""}
	w := New(rt, nil, cpuPolicy())
	got, err := w.Run(context.Background(), job("cpu"))
	if err != nil {
		t.Fatal(err)
	}
	if got.ExitCode != 0 || got.Stdout != "hello\n" {
		t.Errorf("got %+v", got)
	}
	if got.TimedOut {
		t.Error("a job that finished was reported as timed out")
	}
}

// A timeout must still collect output. The logs of a program that ran too long
// are usually the only evidence of what it was doing.
func TestTimeoutStillCollectsOutput(t *testing.T) {
	rt := &fakeRuntime{waitFor: 3 * time.Second, stdout: "partial work\n"}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.Timeout = 150 * time.Millisecond

	got, err := w.Run(context.Background(), j)
	if err != nil {
		t.Fatalf("a timeout should be a result, not an error: %v", err)
	}
	if !got.TimedOut {
		t.Error("timeout not reported")
	}
	if got.Stdout != "partial work\n" {
		t.Errorf("output was discarded on timeout: %q", got.Stdout)
	}
	if got.Error == "" {
		t.Error("timed-out job carries no explanation")
	}
}

// The container must be removed even when it never started — otherwise every
// start failure leaks one.
func TestContainerIsRemovedEvenWhenStartFails(t *testing.T) {
	rt := &fakeRuntime{startErr: errors.New("no such image")}
	w := New(rt, nil, cpuPolicy())
	if _, err := w.Run(context.Background(), job("cpu")); err == nil {
		t.Fatal("expected a start failure")
	}
	// Give the deferred removal a moment; it uses its own context.
	time.Sleep(50 * time.Millisecond)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.removed) == 0 {
		t.Fatal("a container was leaked after a start failure")
	}
}

// Every job gets a fresh container with a read-only root and a memory-backed
// /tmp — one submitter's leftovers must not become the next one's environment.
func TestEachJobGetsAFreshHardenedContainer(t *testing.T) {
	rt := &fakeRuntime{}
	w := New(rt, nil, cpuPolicy())
	for i := 0; i < 3; i++ {
		if _, err := w.Run(context.Background(), job("cpu")); err != nil {
			t.Fatal(err)
		}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.created) != 3 {
		t.Fatalf("created %d containers for 3 jobs", len(rt.created))
	}
	if len(rt.removed) != 3 {
		t.Fatalf("removed %d containers for 3 jobs", len(rt.removed))
	}
	for i, spec := range rt.created {
		if !spec.ReadOnlyRootfs {
			t.Errorf("container %d has a writable root", i)
		}
		if spec.TmpfsMounts["/tmp"] == "" {
			t.Errorf("container %d has no tmpfs /tmp", i)
		}
	}
}

// A job id must never escape into the container name — it arrives from the
// site and is not this node's to trust.
func TestJobIDIsSanitisedIntoTheContainerName(t *testing.T) {
	rt := &fakeRuntime{}
	w := New(rt, nil, cpuPolicy())
	j := job("cpu")
	j.ID = "../../etc/passwd; rm -rf /"
	if _, err := w.Run(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	name := rt.created[0].Name
	for _, bad := range []string{"/", ";", " ", ".."} {
		if strings.Contains(name, bad) {
			t.Errorf("container name %q contains %q", name, bad)
		}
	}
}

func TestSanitiseKeepsNamesBounded(t *testing.T) {
	if got := sanitise(strings.Repeat("a", 500)); len(got) > 48 {
		t.Errorf("name is %d chars", len(got))
	}
	if got := sanitise(""); got == "" {
		t.Error("empty id produced an empty container name")
	}
}
