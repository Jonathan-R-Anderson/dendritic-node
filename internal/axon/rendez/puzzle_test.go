package rendez

import (
	"testing"
	"time"
)

// newTestPuzzle builds a puzzle with a deterministic clock and small difficulty
// band so the tests solve quickly.
func newTestPuzzle() (*AdaptivePuzzle, *time.Time) {
	now := time.Unix(1_000_000, 0)
	p := NewAdaptivePuzzle()
	p.SeedPeriod = 10 * time.Minute
	p.MinBits = 4
	p.MaxBits = 10
	p.OnRate = 20
	p.FullRate = 200
	p.Now = func() time.Time { return now }
	return p, &now
}

// flood drives n introductions for authKey arriving dt apart, advancing the
// injected clock, so the estimator sees a sustained rate of 1/dt per second.
func flood(p *AdaptivePuzzle, now *time.Time, authKey [authKeySize]byte, n int, dt time.Duration) {
	for i := 0; i < n; i++ {
		*now = now.Add(dt)
		p.Observe(authKey)
	}
}

// TestPuzzleOffWhenCalm: a service seeing a trickle of introductions demands no
// proof, so honest clients of an unattacked service pay nothing.
func TestPuzzleOffWhenCalm(t *testing.T) {
	p, now := newTestPuzzle()
	var ak [authKeySize]byte
	ak[0] = 1
	// One introduction per second is well below OnRate=20.
	flood(p, now, ak, 30, time.Second)
	if p.Demanded(ak) {
		t.Fatalf("puzzle demanded under a calm rate (ewma=%.1f)", p.rate[ak].ewma)
	}
	if ch := p.Challenge(ak); ch != nil {
		t.Fatalf("challenge issued when none demanded: %x", ch)
	}
}

// TestPuzzleOnUnderFlood: a high introduction rate turns the puzzle on, and a
// correctly solved proof is admitted while a wrong one is refused.
func TestPuzzleOnUnderFlood(t *testing.T) {
	p, now := newTestPuzzle()
	var ak [authKeySize]byte
	ak[0] = 2
	// A thousand introductions a millisecond apart: a sustained ~1000/s, far
	// above FullRate, so full difficulty is demanded.
	flood(p, now, ak, 1000, time.Millisecond)
	if !p.Demanded(ak) {
		t.Fatal("puzzle not demanded under a heavy flood")
	}
	ch := p.Challenge(ak)
	if ch == nil {
		t.Fatal("no challenge issued under flood")
	}

	var x [pubKeySize]byte
	x[0] = 9
	proof, ok := SolvePuzzle(ch, ak, x)
	if !ok {
		t.Fatal("could not solve the demanded puzzle")
	}
	if err := p.Verify(ak, x, proof); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	// A proof that claims full difficulty but is random bytes must fail.
	bad := make([]byte, len(proof))
	copy(bad, proof)
	bad[len(bad)-1] ^= 0xff
	if err := p.Verify(ak, x, bad); err == nil {
		t.Fatal("a corrupted proof was accepted")
	}
}

// TestPuzzleProofIsBoundToIntroduction: a proof solved for one client ephemeral
// X cannot be replayed onto a different introduction, which is what forces an
// attacker to pay once per flooded introduction rather than once per flood.
func TestPuzzleProofIsBoundToIntroduction(t *testing.T) {
	p, now := newTestPuzzle()
	var ak [authKeySize]byte
	ak[0] = 3
	flood(p, now, ak, 1000, time.Millisecond)
	ch := p.Challenge(ak)

	var x1, x2 [pubKeySize]byte
	x1[0] = 1
	x2[0] = 2
	proof, ok := SolvePuzzle(ch, ak, x1)
	if !ok {
		t.Fatal("solve failed")
	}
	if err := p.Verify(ak, x1, proof); err != nil {
		t.Fatalf("proof rejected for its own introduction: %v", err)
	}
	if err := p.Verify(ak, x2, proof); err == nil {
		t.Fatal("proof bound to X1 was accepted for X2 (replayable across introductions)")
	}
	// Nor can it be replayed onto a different service's auth key.
	var ak2 [authKeySize]byte
	ak2[0] = 99
	if err := p.Verify(ak2, x1, proof); err == nil {
		t.Fatal("proof bound to one auth key was accepted for another")
	}
}

// TestPuzzleSeedExpires: a proof minted under an old seed is refused once two
// rotation periods have passed, bounding how long a precomputed solution lives.
func TestPuzzleSeedExpires(t *testing.T) {
	p, now := newTestPuzzle()
	var ak [authKeySize]byte
	ak[0] = 4
	flood(p, now, ak, 1000, time.Millisecond)
	ch := p.Challenge(ak)
	var x [pubKeySize]byte
	proof, ok := SolvePuzzle(ch, ak, x)
	if !ok {
		t.Fatal("solve failed")
	}
	if err := p.Verify(ak, x, proof); err != nil {
		t.Fatalf("fresh proof rejected: %v", err)
	}
	// Previous epoch still valid (one period of grace).
	*now = now.Add(p.SeedPeriod)
	if err := p.Verify(ak, x, proof); err != nil {
		t.Fatalf("proof rejected within one period of grace: %v", err)
	}
	// Two periods on, the seed is gone.
	*now = now.Add(2 * p.SeedPeriod)
	if err := p.Verify(ak, x, proof); err == nil {
		t.Fatal("an expired-seed proof was accepted")
	}
}

// TestPuzzleTrackingIsBounded: a flood of distinct, never-registered auth keys
// cannot grow the estimator without bound -- the map that drives adaptivity
// must not itself become the exhaustion target.
func TestPuzzleTrackingIsBounded(t *testing.T) {
	p, now := newTestPuzzle()
	for i := 0; i < maxTrackedServices+5000; i++ {
		*now = now.Add(time.Microsecond)
		var ak [authKeySize]byte
		ak[0] = byte(i)
		ak[1] = byte(i >> 8)
		ak[2] = byte(i >> 16)
		p.Observe(ak)
	}
	p.mu.Lock()
	n := len(p.rate)
	p.mu.Unlock()
	if n > maxTrackedServices {
		t.Fatalf("estimator grew past its cap: %d > %d", n, maxTrackedServices)
	}
}

// TestIntroPointAdmissionUnderFlood drives the real AdaptivePuzzle through the
// intro point exactly as the relay does: a calm introduction is admitted with
// no proof, a flood flips the point to PUZZLE_REQUIRED and hands back a
// challenge, and a client that solves that challenge is then admitted -- the
// whole point of the feature, that every hidden service gets flood protection
// without registering anything.
func TestIntroPointAdmissionUnderFlood(t *testing.T) {
	p, now := newTestPuzzle()
	ip := NewIntroPoint()
	ip.Puzzle = p
	ip.Limit = nil // isolate the puzzle from the rate limiter here

	var ak [authKeySize]byte
	ak[0] = 7
	ip.Establish(ak, CircuitRef(42))

	// Calm: one introduction, admitted with no proof.
	var x [pubKeySize]byte
	x[0] = 1
	calm := &Introduce1{AuthKeyID: ak, X: x}
	if c, st, err := ip.Admit(calm); err != nil || st != AckOK || c != 42 {
		t.Fatalf("calm introduction not admitted: c=%d st=%s err=%v", c, st, err)
	}

	// Flood: the service is now hammered. The next introduction is refused with
	// PUZZLE_REQUIRED and the point offers a challenge.
	flood(p, now, ak, 1000, time.Millisecond)
	var x2 [pubKeySize]byte
	x2[0] = 2
	attempt := &Introduce1{AuthKeyID: ak, X: x2}
	c, st, err := ip.Admit(attempt)
	if st != AckPuzzleRequired || c != 0 {
		t.Fatalf("flooded introduction without a proof should be refused: c=%d st=%s err=%v", c, st, err)
	}
	ch := ip.ChallengeParams(ak)
	if ch == nil {
		t.Fatal("no challenge offered under flood")
	}

	// The client solves and retries on the same introduction (same X).
	proof, ok := SolvePuzzle(ch, ak, x2)
	if !ok {
		t.Fatal("client could not solve the offered challenge")
	}
	attempt.PuzzleProof = proof
	if c, st, err := ip.Admit(attempt); err != nil || st != AckOK || c != 42 {
		t.Fatalf("solved introduction not admitted: c=%d st=%s err=%v", c, st, err)
	}
}

// TestUnsafeModeClearedByAdaptivePuzzle: wiring the real puzzle takes the intro
// point out of the declared-unsafe no-puzzle mode.
func TestUnsafeModeClearedByAdaptivePuzzle(t *testing.T) {
	ip := NewIntroPoint()
	if len(ip.UnsafeModes()) != 1 {
		t.Fatal("a nil-puzzle intro point should declare the unsafe mode")
	}
	ip.Puzzle = NewAdaptivePuzzle()
	if len(ip.UnsafeModes()) != 0 {
		t.Fatalf("AdaptivePuzzle still reports unsafe: %v", ip.UnsafeModes())
	}
}
