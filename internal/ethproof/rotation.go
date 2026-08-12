package ethproof

// Sync committee rotation — roadmap P12-5.5.
//
// THE INVARIANT
// -------------
//	A committee becomes trusted ONLY by being authenticated with a committee
//	that was already trusted.
//
// The failure this prevents is circular and looks entirely reasonable in code:
//
//	RPC:  "here is the new committee, and here is its signature"
//	node: "the signature checks out against that committee — accepted"
//
// That verifies a message against itself, which every forgery satisfies. So the
// committee used to check an update is ALWAYS taken from the trusted state, and
// the committee an update carries is only ever a candidate — proven into the
// attested state by a Merkle branch, and adopted only after the update itself
// has been authenticated by a committee we already had.
//
//	sealed checkpoint
//	      │ committee N
//	      ▼
//	update signed by N  ──►  authenticated  ──►  adopt N+1 from its branch
//	                                                    │
//	                                                    ▼
//	                                       update signed by N+1  ──►  ...
//
// WHY PERIODS MATTER
// ------------------
// A committee serves one period of 8192 slots (~27 hours). An update signed in
// period P must be checked against the committee for period P, and an
// implementation that reached for whichever committee it happened to hold would
// accept a signature from the wrong set — valid, and about the wrong 27 hours.
//
// FORK-DEPENDENT LAYOUT TRAVELS WITH THE STATE
// --------------------------------------------
// The generalized indices are container positions, and containers changed shape
// across forks. A branch verified at a stale index proves a TRUE statement about
// the WRONG FIELD, which is the quietest failure available here. So the spec
// version is carried on the state and the indices are looked up from it rather
// than being package constants anybody can reach.
//
// Electra's values are deliberately absent rather than guessed: IndicesFor
// returns an error for it. Failing to start is recoverable; verifying against
// the wrong field is not.

import (
	"errors"
	"fmt"
)

// SlotsPerSyncCommitteePeriod is 32 slots per epoch × 256 epochs.
const SlotsPerSyncCommitteePeriod = 32 * 256

// SyncCommitteePeriod is the period a slot belongs to.
func SyncCommitteePeriod(slot uint64) uint64 {
	return slot / SlotsPerSyncCommitteePeriod
}

// SpecVersion names the fork whose container layout is in use.
type SpecVersion string

const (
	// SpecAltair covers Altair through Deneb, whose light client containers
	// share one layout.
	SpecAltair SpecVersion = "altair"
	// SpecElectra changed the generalized indices. Its values are NOT recorded
	// here — see IndicesFor.
	SpecElectra SpecVersion = "electra"
)

// ForkIndices are the generalized indices for one fork's container layout.
type ForkIndices struct {
	FinalizedRoot        uint64
	NextSyncCommittee    uint64
	CurrentSyncCommittee uint64
}

// ErrSpecUnsupported means the layout for a fork has not been established here.
var ErrSpecUnsupported = errors.New("lightclient: generalized indices for this fork are not recorded")

// IndicesFor returns the container layout for a fork.
//
// Electra returns an error ON PURPOSE. Its indices differ from Altair's and the
// correct values must be taken from the specification, not inferred — a branch
// verified at a stale index proves a true statement about a different field,
// and nothing downstream would notice. Refusing to start is the recoverable
// failure; the other one is not.
func IndicesFor(v SpecVersion) (ForkIndices, error) {
	switch v {
	case SpecAltair:
		return ForkIndices{
			FinalizedRoot:        FinalizedRootIndex,
			NextSyncCommittee:    NextSyncCommitteeIndex,
			CurrentSyncCommittee: CurrentSyncCommitteeIndex,
		}, nil
	case SpecElectra:
		return ForkIndices{}, fmt.Errorf(
			"%w: %q moved them; take the values from the spec and add them here", ErrSpecUnsupported, v)
	default:
		return ForkIndices{}, fmt.Errorf("%w: %q", ErrSpecUnsupported, v)
	}
}

var (
	// ErrWrongPeriod means the update was signed in a period this state cannot
	// check — too old, or further ahead than the next committee covers.
	ErrWrongPeriod = errors.New("lightclient: update belongs to a sync committee period this state cannot authenticate")
	// ErrNextCommitteeUnknown means an update needs the next committee and this
	// state has not authenticated one.
	ErrNextCommitteeUnknown = errors.New("lightclient: update is for the next period and no next committee is known")
	// ErrCommitteeConflict means an update offers a different committee for a
	// period this state has already fixed.
	ErrCommitteeConflict = errors.New("lightclient: update contradicts an already-authenticated committee")
)

// Period is the period this state's finalised head sits in.
func (s *LightClientState) Period() uint64 {
	return SyncCommitteePeriod(s.FinalizedHeader.Slot)
}

// committeeFor returns the committee authorised to sign in a given period.
//
// From THIS STATE, never from the update. The whole rotation design is this one
// function refusing to look anywhere else.
func (s *LightClientState) committeeFor(period uint64) (*SyncCommittee, error) {
	switch period {
	case s.Period():
		if s.CurrentCommittee == nil {
			return nil, ErrCommitteeUnknown
		}
		return s.CurrentCommittee, nil
	case s.Period() + 1:
		if s.NextCommittee == nil {
			return nil, ErrNextCommitteeUnknown
		}
		return s.NextCommittee, nil
	default:
		return nil, fmt.Errorf("%w: update is in period %d, this state covers %d and %d",
			ErrWrongPeriod, period, s.Period(), s.Period()+1)
	}
}

// ApplyRotatingUpdate authenticates an update and rotates committees.
//
// ATOMIC. Nothing on the receiver is written until every check has passed, so a
// rejected update leaves the state exactly as it was — including the case where
// the signature fails after the structure verified.
func (s *LightClientState) ApplyRotatingUpdate(u *Update, v SyncCommitteeVerifier) error {
	if v == nil {
		return errors.New("lightclient: no signature verifier; refusing to advance")
	}
	indices, err := IndicesFor(s.Spec)
	if err != nil {
		return err
	}

	// 1. Structure, against the layout THIS STATE says is in force.
	if err := s.validateStructureWith(u, indices); err != nil {
		return err
	}

	// 2. Which committee is authorised for the period this was SIGNED in — not
	//    the period it talks about. Taken from this state.
	signaturePeriod := SyncCommitteePeriod(u.SignatureSlot)
	committee, err := s.committeeFor(signaturePeriod)
	if err != nil {
		return err
	}

	// 3. An update must not contradict a committee already fixed for a period.
	//    Two different committees for one period is an ambiguity, and resolving
	//    it by preferring the newer message would let a later forgery win.
	if u.NextCommittee != nil && s.NextCommittee != nil &&
		signaturePeriod == s.Period() {
		known, err := s.NextCommittee.HashTreeRoot()
		if err != nil {
			return err
		}
		offered, err := u.NextCommittee.HashTreeRoot()
		if err != nil {
			return err
		}
		if known != offered {
			return fmt.Errorf("%w: period %d already has a different next committee",
				ErrCommitteeConflict, signaturePeriod+1)
		}
	}

	// 4. The signature, last and only now.
	signingRoot, err := s.SigningRootFor(u)
	if err != nil {
		return err
	}
	if err := v.VerifySyncCommitteeSignature(
		signingRoot, committee, u.Participation, u.Signature); err != nil {
		return fmt.Errorf("lightclient: sync committee signature: %w", err)
	}

	// 5. Everything passed. Only now is anything written.
	previousPeriod := s.Period()
	s.FinalizedHeader = u.FinalizedHeader
	// The attested header was signed by the committee, so it is Verified — a
	// weaker claim than the finalised one above, recorded separately because
	// the two levels must never be read off the same field.
	if !s.optimistic.known || u.AttestedHeader.Slot > s.optimistic.header.Slot {
		s.optimistic.header = u.AttestedHeader
		s.optimistic.known = true
	}

	if newPeriod := s.Period(); newPeriod > previousPeriod {
		// The head crossed a boundary: the committee that was "next" is now
		// current. Rotating rather than re-fetching is the point — the new
		// current committee was authenticated in the old period, by a committee
		// that was itself authenticated, all the way back to the checkpoint.
		if newPeriod == previousPeriod+1 && s.NextCommittee != nil {
			s.CurrentCommittee = s.NextCommittee
			s.NextCommittee = nil
		}
	}
	if u.NextCommittee != nil {
		s.NextCommittee = u.NextCommittee
	}
	return nil
}

// validateStructureWith is ValidateStructure against explicit fork indices.
//
// The exported ValidateStructure keeps the package constants for callers that
// have not adopted a spec version; this is the path rotation uses, and it takes
// the layout from the state so a branch cannot be checked against a fork the
// state is not following.
func (s *LightClientState) validateStructureWith(u *Update, indices ForkIndices) error {
	if u.FinalizedHeader.Slot <= s.FinalizedHeader.Slot {
		return fmt.Errorf("%w: finalised slot %d is not beyond the known %d",
			ErrUpdateStale, u.FinalizedHeader.Slot, s.FinalizedHeader.Slot)
	}
	if u.AttestedHeader.Slot < u.FinalizedHeader.Slot {
		return fmt.Errorf("lightclient: attested slot %d precedes the finalised slot %d",
			u.AttestedHeader.Slot, u.FinalizedHeader.Slot)
	}
	if u.SignatureSlot <= u.AttestedHeader.Slot {
		return fmt.Errorf("lightclient: signature slot %d does not follow the attested slot %d",
			u.SignatureSlot, u.AttestedHeader.Slot)
	}
	if got := u.Participation.Count(); got < MinParticipation {
		return fmt.Errorf("%w: %d of %d, need %d",
			ErrInsufficientParticipation, got, SyncCommitteeSize, MinParticipation)
	}

	finalizedRoot, err := u.FinalizedHeader.HashTreeRoot()
	if err != nil {
		return err
	}
	if err := VerifyBranch(finalizedRoot, u.FinalityBranch,
		indices.FinalizedRoot, u.AttestedHeader.StateRoot); err != nil {
		return fmt.Errorf("%w: finality: %v", ErrBranchWrongField, err)
	}

	if u.NextCommittee != nil {
		committeeRoot, err := u.NextCommittee.HashTreeRoot()
		if err != nil {
			return err
		}
		if err := VerifyBranch(committeeRoot, u.NextCommitteeBranch,
			indices.NextSyncCommittee, u.AttestedHeader.StateRoot); err != nil {
			return fmt.Errorf("%w: next committee: %v", ErrBranchWrongField, err)
		}
	}
	return nil
}
