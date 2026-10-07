package rendez

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/bits"
	"sync"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/params"
)

// AdaptivePuzzle is the production INTRODUCE1 admission puzzle (R10 / P6a).
//
// It turns the intro point's structural blindness into an active DoS defence. A
// hidden service exposes no address, so the only flood an attacker can mount is
// INTRODUCE1 pressure at its intro points. This prices that flood: a proof is a
// hashcash solution bound to the introduction, demanded only while a service is
// actually under pressure, at a difficulty that climbs with the pressure.
//
// Construction. A proof admits an introduction iff
//
//	leadingZeroBits( SHA256(seed ‖ authKey ‖ X ‖ bits ‖ nonce) ) >= bits
//
// where `seed` is a PUBLIC per-intro-point value rotated every SeedPeriod and
// `nonce` is the 8-byte search output. Binding to X -- the client's fresh
// ephemeral, which the INTRODUCE1 AAD already pins -- means every introduction
// needs its own solve and a solved nonce cannot be replayed onto a different
// introduction. The seed being public lets a client solve without learning any
// secret; rotation bounds precomputation. The verifier recomputes one SHA-256
// and holds nothing per client beyond a bounded per-service rate estimate, so
// it cannot itself be turned into the memory-exhaustion target.
//
// Adaptivity. Demanded(authKey) is false while a service's introduction rate is
// below params.IntroPuzzleOnRate -- the common case -- so honest clients of an
// unattacked service pay nothing. Above it, the demanded difficulty ramps from
// IntroPuzzleMinBits to IntroPuzzleMaxBits as the rate approaches
// IntroPuzzleFullRate. Pressure is tracked per auth key, so an attack on one
// service never taxes the clients of another sharing the same intro point.
type AdaptivePuzzle struct {
	// SeedPeriod, MinBits, MaxBits, OnRate, FullRate default to the params
	// values when zero; tests override them.
	SeedPeriod time.Duration
	MinBits    int
	MaxBits    int
	OnRate     float64
	FullRate   float64
	// Now is the clock; nil means time.Now. Tests inject a deterministic one.
	Now func() time.Time

	root [32]byte // process-local secret from which public seeds derive

	mu   sync.Mutex
	rate map[[authKeySize]byte]*rateEst
}

// rateEst is an exponentially weighted estimate of one service's introduction
// rate in arrivals per second, plus the difficulty last demanded for it.
type rateEst struct {
	ewma     float64
	last     time.Time
	demanded int
}

// maxTrackedServices caps the per-service estimator map so a flood of random,
// never-registered auth keys cannot grow it without bound. A real flood
// concentrates on a few target keys, which stay hot; random keys are each seen
// about once, never cross the on-rate, and are evicted.
const maxTrackedServices = 8192

// rateTau is the estimator's time constant: pressure built over roughly the
// last second drives the difficulty, so a burst is felt quickly and a lull
// forgotten quickly.
const rateTau = 1.0

// NewAdaptivePuzzle builds a puzzle with a fresh random seed root.
func NewAdaptivePuzzle() *AdaptivePuzzle {
	p := &AdaptivePuzzle{rate: map[[authKeySize]byte]*rateEst{}}
	if _, err := io.ReadFull(rand.Reader, p.root[:]); err != nil {
		// A process that cannot read 32 random bytes cannot run the overlay
		// safely at all; fail loudly rather than serve a predictable seed.
		panic("axon/rendez: cannot seed admission puzzle: " + err.Error())
	}
	return p
}

func (p *AdaptivePuzzle) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *AdaptivePuzzle) seedPeriod() time.Duration {
	if p.SeedPeriod > 0 {
		return p.SeedPeriod
	}
	return params.IntroPuzzleSeedPeriod
}

func (p *AdaptivePuzzle) minBits() int {
	if p.MinBits > 0 {
		return p.MinBits
	}
	return params.IntroPuzzleMinBits
}

func (p *AdaptivePuzzle) maxBits() int {
	if p.MaxBits > 0 {
		return p.MaxBits
	}
	return params.IntroPuzzleMaxBits
}

func (p *AdaptivePuzzle) onRate() float64 {
	if p.OnRate > 0 {
		return p.OnRate
	}
	return params.IntroPuzzleOnRate
}

func (p *AdaptivePuzzle) fullRate() float64 {
	if p.FullRate > 0 {
		return p.FullRate
	}
	return params.IntroPuzzleFullRate
}

// epoch is the seed rotation counter for a time.
func (p *AdaptivePuzzle) epoch(t time.Time) uint64 {
	return uint64(t.UnixNano() / int64(p.seedPeriod()))
}

// seedFor derives the public seed for an epoch. It reveals nothing about root:
// a client that holds the seed cannot derive root or any other epoch's seed.
func (p *AdaptivePuzzle) seedFor(epoch uint64) [32]byte {
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], epoch)
	return sha256.Sum256(append(append([]byte{}, p.root[:]...), e[:]...))
}

// bitsForRate maps a service's introduction rate to a demanded difficulty.
func (p *AdaptivePuzzle) bitsForRate(r float64) int {
	on, full := p.onRate(), p.fullRate()
	if r < on {
		return 0
	}
	if r >= full {
		return p.maxBits()
	}
	lo, hi := p.minBits(), p.maxBits()
	frac := (r - on) / (full - on)
	return lo + int(frac*float64(hi-lo)+0.5)
}

// Observe records an arrival for authKey and recomputes its demanded difficulty.
func (p *AdaptivePuzzle) Observe(authKey [authKeySize]byte) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.rate[authKey]
	if !ok {
		if len(p.rate) >= maxTrackedServices {
			p.evictOneLocked()
		}
		e = &rateEst{last: now}
		p.rate[authKey] = e
		// First arrival establishes a baseline; no rate yet.
		return
	}
	dt := now.Sub(e.last).Seconds()
	if dt <= 0 {
		dt = 1e-6
	}
	inst := 1.0 / dt
	alpha := 1 - math.Exp(-dt/rateTau)
	e.ewma += alpha * (inst - e.ewma)
	e.last = now
	e.demanded = p.bitsForRate(e.ewma)
}

// evictOneLocked drops one tracked service to keep the map bounded. Caller holds
// p.mu. Any choice is fine: a hot (attacked) key is re-created and re-heated on
// its very next arrival, while the cold keys this sheds were not demanding a
// proof anyway.
func (p *AdaptivePuzzle) evictOneLocked() {
	for k := range p.rate {
		delete(p.rate, k)
		return
	}
}

// demandedBits returns the difficulty currently demanded for authKey.
func (p *AdaptivePuzzle) demandedBits(authKey [authKeySize]byte) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.rate[authKey]; ok {
		return e.demanded
	}
	return 0
}

// Demanded reports whether a proof is currently required for authKey.
func (p *AdaptivePuzzle) Demanded(authKey [authKeySize]byte) bool {
	return p.demandedBits(authKey) > 0
}

// Challenge is the params a client needs to solve for authKey: the current
// epoch, the demanded difficulty, and the public seed. nil when none is due.
func (p *AdaptivePuzzle) Challenge(authKey [authKeySize]byte) []byte {
	b := p.demandedBits(authKey)
	if b <= 0 {
		return nil
	}
	return encodeChallenge(p.epoch(p.now()), b, p.seedFor(p.epoch(p.now())))
}

// Required is true: an AdaptivePuzzle can always be made to demand a proof.
func (p *AdaptivePuzzle) Required() bool { return true }

// verifySlackBits lets a proof solved for the difficulty demanded an instant
// earlier still pass when a continuing flood has just nudged the demand up by a
// bit, so a client that solved honestly is not rejected into a resolve loop.
const verifySlackBits = 2

// Verify checks that proof is a valid, current, correctly-bound solution.
func (p *AdaptivePuzzle) Verify(authKey [authKeySize]byte, x [pubKeySize]byte, proof []byte) error {
	epoch, pbits, nonce, err := decodeProof(proof)
	if err != nil {
		return err
	}
	// The proof must meet the difficulty currently demanded (less a small slack
	// for an in-flight demand increase), and never undercut the floor.
	need := p.demandedBits(authKey)
	if need < p.minBits() {
		need = p.minBits()
	}
	if pbits < need-verifySlackBits || pbits < p.minBits() {
		return errors.New("axon/rendez: puzzle proof too weak for current demand")
	}
	if pbits > p.maxBits() {
		return errors.New("axon/rendez: puzzle proof difficulty out of range")
	}
	// The seed must be this epoch's or the immediately previous one (rotation
	// grace for in-flight introductions and clock skew).
	cur := p.epoch(p.now())
	if epoch != cur && epoch != cur-1 {
		return errors.New("axon/rendez: puzzle proof seed expired")
	}
	seed := p.seedFor(epoch)
	if leadingZeroBits(puzzleDigest(seed, authKey, x, pbits, nonce)) < pbits {
		return errors.New("axon/rendez: puzzle proof does not meet difficulty")
	}
	return nil
}

// SolvePuzzle finds a nonce admitting an introduction for (authKey, x) under the
// challenge the intro point returned in INTRODUCE_ACK.PuzzleParams. It is the
// client-side cost, run only when a service is under attack. ok is false if the
// challenge is malformed or no solution was found within the attempt cap (which
// only happens at difficulties far above what MaxBits permits).
func SolvePuzzle(challenge []byte, authKey [authKeySize]byte, x [pubKeySize]byte) ([]byte, bool) {
	epoch, pbits, seed, err := decodeChallenge(challenge)
	if err != nil || pbits <= 0 {
		return nil, false
	}
	// Cap the search generously above the honest worst case (2^MaxBits), so an
	// absurd demanded difficulty fails fast rather than spinning forever.
	limit := uint64(1) << uint(minInt(pbits+8, 40))
	for nonce := uint64(0); nonce < limit; nonce++ {
		if leadingZeroBits(puzzleDigest(seed, authKey, x, pbits, nonce)) >= pbits {
			return encodeProof(epoch, pbits, nonce), true
		}
	}
	return nil, false
}

// puzzleDigest is the hash both solver and verifier compute over the same
// preimage: the public seed, the service auth key, the client's ephemeral, the
// difficulty, and the trial nonce.
func puzzleDigest(seed, authKey [32]byte, x [pubKeySize]byte, pbits int, nonce uint64) []byte {
	h := sha256.New()
	h.Write(seed[:])
	h.Write(authKey[:])
	h.Write(x[:])
	h.Write([]byte{byte(pbits)})
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], nonce)
	h.Write(n[:])
	return h.Sum(nil)
}

// leadingZeroBits counts the leading zero bits of a digest.
func leadingZeroBits(h []byte) int {
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		n += bits.LeadingZeros8(b)
		break
	}
	return n
}

// Wire encodings. Challenge: epoch(8) ‖ bits(1) ‖ seed(32). Proof: epoch(8) ‖
// bits(1) ‖ nonce(8). Both are fixed-size and self-describing.

func encodeChallenge(epoch uint64, pbits int, seed [32]byte) []byte {
	b := make([]byte, 0, 8+1+32)
	b = binary.BigEndian.AppendUint64(b, epoch)
	b = append(b, byte(pbits))
	return append(b, seed[:]...)
}

func decodeChallenge(b []byte) (epoch uint64, pbits int, seed [32]byte, err error) {
	if len(b) != 8+1+32 {
		return 0, 0, seed, errors.New("axon/rendez: malformed puzzle challenge")
	}
	epoch = binary.BigEndian.Uint64(b[:8])
	pbits = int(b[8])
	copy(seed[:], b[9:])
	return epoch, pbits, seed, nil
}

func encodeProof(epoch uint64, pbits int, nonce uint64) []byte {
	b := make([]byte, 0, 8+1+8)
	b = binary.BigEndian.AppendUint64(b, epoch)
	b = append(b, byte(pbits))
	return binary.BigEndian.AppendUint64(b, nonce)
}

func decodeProof(b []byte) (epoch uint64, pbits int, nonce uint64, err error) {
	if len(b) != 8+1+8 {
		return 0, 0, 0, errors.New("axon/rendez: malformed puzzle proof")
	}
	epoch = binary.BigEndian.Uint64(b[:8])
	pbits = int(b[8])
	nonce = binary.BigEndian.Uint64(b[9:])
	return epoch, pbits, nonce, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
