package channel

// The deployment gate, as code — roadmap P12.
//
// WHY THIS IS NOT A CHECKLIST IN A DOCUMENT
// -----------------------------------------
// P10 produced a challengePeriod of 8 hours from eight terms, seven of which
// are estimates about a network nobody has run this against. The figure may
// well be right. What is certainly true is that nobody has checked, and the
// value is immutable once deployed.
//
// A document saying "validate before deploying" is a document somebody reads
// once. This makes the rule mechanical:
//
//	DeployableChallengePeriod() returns an ERROR until every term that makes a
//	claim about the world has evidence behind it.
//
// So the deployment script cannot get a number to deploy with, and the failure
// says which terms are still guesses. That is the whole of P12's contribution
// to safety — the rest is the measuring, which needs a chain.
//
// WHAT COUNTS AS EVIDENCE
// -----------------------
// A measurement, its sample count, the chain it was taken on and how. Not a
// tick in a box: "we validated inclusion" is not checkable, and an assertion
// nobody can check is the thing this exists to replace.
//
// Evidence must also SUPPORT the budgeted value. A measurement showing
// inclusion takes 45 minutes does not validate a 30-minute budget — it refutes
// it, and the correct response is to raise the term and re-derive, not to
// record the measurement and carry on.

import (
	"fmt"
	"sort"
	"time"
)

// Evidence is one term, measured against a real chain.
type Evidence struct {
	// Term names the ChallengeBudget field, as Terms() spells it.
	Term string
	// Measured is the WORST observed value, not the average. The budget is a
	// worst-case sum; feeding it a mean would quietly halve it.
	Measured time.Duration
	// Samples is how many observations produced it. One sample is an anecdote,
	// and the threshold below says so.
	Samples int
	// ChainID is where it was measured. A measurement from a testnet does not
	// validate a mainnet deployment, and this is what makes that checkable.
	ChainID int64
	// Method is how, in a sentence. For a human reading the record later.
	Method string
	// TakenAt is a unix timestamp, PASSED IN rather than read from a clock, so
	// a validation record is reproducible.
	TakenAt int64
}

// MinEvidenceSamples is the fewest observations that count.
//
// Thirty is not statistically magic. It is enough that a single unlucky block
// or one slow RPC call cannot define the answer, which is the failure mode a
// small sample actually has here.
const MinEvidenceSamples = 30

// EvidenceMaxAge is how long a measurement stays good.
//
// Networks change: fee markets, client releases, an L2's sequencer policy. A
// year-old measurement of inclusion time is a historical note, not evidence
// about the chain being deployed to now.
const EvidenceMaxAge = 90 * 24 * time.Hour

// termsNeedingEvidence lists the budget terms that make a claim about the
// world, with the reason each one needs checking.
//
// Two are deliberately absent:
//
//	local work  — measured in-process by TestLocalPathFitsItsBudget, on the
//	              machine that will run it. Nothing a chain could add.
//	safety      — deliberate padding for unmodelled failure. There is nothing
//	              to measure; it is an admission, not a claim.
var termsNeedingEvidence = map[string]string{
	"detection":         "the sweep must actually complete within it, at the channel count this node will hold",
	"watchtower outage": "an operational commitment: how long can this really be down before somebody acts",
	"inclusion":         "broadcast to first confirmation on the target chain, under congestion",
	"repricing":         "a full replacement cycle at a higher fee",
	"rpc failure":       "a dead or lying endpoint, plus failover — requires more than one endpoint",
	"reorg depth":       "how deep a reorganisation the target chain actually sustains",
}

// ValidatedBudget is a budget plus what has been checked about it.
type ValidatedBudget struct {
	Budget ChallengeBudget
	// ChainID is the deployment this validation is FOR. Evidence from anywhere
	// else does not count towards it.
	ChainID  int64
	Evidence map[string]Evidence
}

// NewValidatedBudget starts an empty validation for a chain.
func NewValidatedBudget(chainID int64, budget ChallengeBudget) *ValidatedBudget {
	return &ValidatedBudget{Budget: budget, ChainID: chainID, Evidence: map[string]Evidence{}}
}

// Record files evidence for a term.
//
// Refuses evidence that does not belong to this deployment, is too thin, or
// contradicts the budget — because recording a refutation as though it were a
// confirmation is worse than having no record at all.
func (v *ValidatedBudget) Record(e Evidence) error {
	reason, wanted := termsNeedingEvidence[e.Term]
	if !wanted {
		if _, known := v.budgeted(e.Term); !known {
			return fmt.Errorf("validation: %q is not a budget term", e.Term)
		}
		return fmt.Errorf("validation: %q does not take evidence", e.Term)
	}
	if e.ChainID != v.ChainID {
		return fmt.Errorf(
			"validation: %q was measured on chain %d, this budget is for chain %d",
			e.Term, e.ChainID, v.ChainID)
	}
	if e.Samples < MinEvidenceSamples {
		return fmt.Errorf("validation: %q has %d samples, need %d (%s)",
			e.Term, e.Samples, MinEvidenceSamples, reason)
	}
	if e.Method == "" {
		return fmt.Errorf("validation: %q has no method recorded; an unrepeatable measurement is not evidence", e.Term)
	}
	budgeted, _ := v.budgeted(e.Term)
	if e.Measured > budgeted {
		// The measurement refutes the budget. Raising the term and re-deriving
		// is the correct response; filing this quietly is not.
		return fmt.Errorf(
			"validation: %q measured %s but is budgeted at %s — raise the term and re-derive",
			e.Term, e.Measured, budgeted)
	}
	v.Evidence[e.Term] = e
	return nil
}

func (v *ValidatedBudget) budgeted(term string) (time.Duration, bool) {
	for _, t := range v.Budget.Terms() {
		if t.Name == term {
			return t.Dur, true
		}
	}
	return 0, false
}

// Unvalidated lists the terms still resting on nothing, in a stable order.
func (v *ValidatedBudget) Unvalidated(now int64) []string {
	var out []string
	for term := range termsNeedingEvidence {
		e, ok := v.Evidence[term]
		if !ok {
			out = append(out, term)
			continue
		}
		if now > 0 && time.Duration(now-e.TakenAt)*time.Second > EvidenceMaxAge {
			out = append(out, term+" (evidence expired)")
		}
	}
	sort.Strings(out)
	return out
}

// DeployableChallengePeriod returns the value to deploy with, or an error
// naming what is still unvalidated.
//
// The error is the point. A deployment script asks this for a number and
// cannot get one while any term is a guess, which is a far stronger guarantee
// than a person remembering to check.
func (v *ValidatedBudget) DeployableChallengePeriod(now int64) (int64, error) {
	missing := v.Unvalidated(now)
	if len(missing) > 0 {
		return 0, fmt.Errorf(
			"validation: challengePeriod is immutable and %d term(s) are still unvalidated on chain %d: %v",
			len(missing), v.ChainID, missing)
	}
	return int64(v.Budget.Recommend() / time.Second), nil
}

// Report renders the state of validation for a human.
func (v *ValidatedBudget) Report(now int64) string {
	out := fmt.Sprintf("challengePeriod validation for chain %d\n", v.ChainID)
	for _, t := range v.Budget.Terms() {
		reason, needs := termsNeedingEvidence[t.Name]
		switch {
		case !needs:
			out += fmt.Sprintf("  %-18s %-8s  n/a — %s\n", t.Name, t.Dur,
				exemptReason(t.Name))
		default:
			if e, ok := v.Evidence[t.Name]; ok {
				out += fmt.Sprintf("  %-18s %-8s  measured %s over %d samples (%s)\n",
					t.Name, t.Dur, e.Measured, e.Samples, e.Method)
			} else {
				out += fmt.Sprintf("  %-18s %-8s  UNVALIDATED — %s\n", t.Name, t.Dur, reason)
			}
		}
	}
	if seconds, err := v.DeployableChallengePeriod(now); err == nil {
		out += fmt.Sprintf("\n  DEPLOYABLE: challengePeriod = %d seconds\n", seconds)
	} else {
		out += fmt.Sprintf("\n  NOT DEPLOYABLE: %v\n", err)
	}
	return out
}

func exemptReason(term string) string {
	switch term {
	case "local work":
		return "measured in-process by TestLocalPathFitsItsBudget"
	case "safety":
		return "padding for unmodelled failure; nothing to measure"
	}
	return "no evidence required"
}
