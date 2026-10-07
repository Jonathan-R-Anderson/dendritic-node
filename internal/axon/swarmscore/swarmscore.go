// Package swarmscore turns a stream of content reports about a hidden service
// into a grade and a DAO-escalation signal, using a thermal ("temperature")
// model so the network self-regulates without a coordinator.
//
// The idea is stigmergic — swarm behaviour out of a shared trail, like ants on
// a pheromone gradient. Every node sees the same report records (published to
// the DHT, §89), so every node computes the SAME temperature for a service from
// them. No node is in charge; the collective reaction — hotter services get
// worse grades and faster DAO votes — emerges from each node running this one
// deterministic function over the shared reports.
//
// Temperature, heating and cooling:
//
//   - A service HEATS with the frequency of reports against it, and heats
//     FASTER when that frequency is rising (positive acceleration) — a sudden
//     surge is treated as more urgent than a steady trickle of the same volume.
//     Recent reports weigh more than old ones (an exponential recency decay), so
//     temperature also falls on its own as a burst ages out.
//   - It COOLS back to a good grade once the burst has settled. "Settled" is the
//     frequency's dispersion falling below its level: when the standard deviation
//     of the per-bucket report counts over the trailing window drops below their
//     mean, the swarm reads the event as over, and the service returns to a good
//     grade. A bursty history (high variance) stays hot; a steady or quiet one
//     (low variance) cools — equal report VOLUME, opposite outcomes, exactly as a
//     burst detector should behave.
//
// Escalation:
//
//   - As temperature rises, the push to act is ACCELERATED: above ProposeTemp the
//     assessment recommends opening a DAO suspension proposal, and the
//     recommended voting window SHRINKS as temperature climbs (a hotter service
//     gets a faster vote), down to MinVoteWindow. Above UrgentTemp it is flagged
//     urgent.
//
// The output grades feed the signed service-policy document
// (internal/axon/servicepolicy); the escalation signal drives the DAO suspension
// contract (contracts/suspension). This package computes; it does not publish or
// vote.
package swarmscore

import (
	"math"
	"sort"
	"time"
)

// Params tunes the thermal model. Zero values are replaced by DefaultParams in
// Assess, so callers may set only the fields they care about.
type Params struct {
	Bucket         time.Duration // width of one frequency bucket (default 1h)
	Window         int           // number of trailing buckets considered (default 24)
	Decay          float64       // per-bucket recency weight in (0,1) (default 0.8)
	Accel          float64       // heat added per unit of positive frequency acceleration (default 1)
	Scale          float64       // temperature at which the grade reaches ~37 (F) (default 10)
	CoolMul        float64       // temperature multiplier once settled (default 0.15)
	ProposeTemp    float64       // temperature above which a DAO proposal is recommended (default 5)
	UrgentTemp     float64       // temperature above which the situation is urgent (default 15)
	BaseVoteWindow time.Duration // DAO voting window at ProposeTemp (default 7d)
	MinVoteWindow  time.Duration // floor the accelerated window cannot go below (default 6h)
}

// DefaultParams is the model's out-of-the-box tuning.
func DefaultParams() Params {
	return Params{
		Bucket: time.Hour, Window: 24, Decay: 0.8, Accel: 1, Scale: 10,
		CoolMul: 0.15, ProposeTemp: 5, UrgentTemp: 15,
		BaseVoteWindow: 7 * 24 * time.Hour, MinVoteWindow: 6 * time.Hour,
	}
}

func (p Params) withDefaults() Params {
	d := DefaultParams()
	if p.Bucket > 0 {
		d.Bucket = p.Bucket
	}
	if p.Window > 0 {
		d.Window = p.Window
	}
	if p.Decay > 0 {
		d.Decay = p.Decay
	}
	if p.Accel > 0 {
		d.Accel = p.Accel
	}
	if p.Scale > 0 {
		d.Scale = p.Scale
	}
	if p.CoolMul > 0 {
		d.CoolMul = p.CoolMul
	}
	if p.ProposeTemp > 0 {
		d.ProposeTemp = p.ProposeTemp
	}
	if p.UrgentTemp > 0 {
		d.UrgentTemp = p.UrgentTemp
	}
	if p.BaseVoteWindow > 0 {
		d.BaseVoteWindow = p.BaseVoteWindow
	}
	if p.MinVoteWindow > 0 {
		d.MinVoteWindow = p.MinVoteWindow
	}
	return d
}

// Escalation levels.
const (
	Stable   = "stable"   // nothing to do
	Elevated = "elevated" // propose a DAO vote; accelerate it as temperature climbs
	Urgent   = "urgent"   // hot enough to warrant the fastest allowed vote
)

// Report is one report event about a subject (a service's .key.axon address or
// its key hash — any stable string identifier).
type Report struct {
	Subject string
	At      time.Time
}

// Assessment is the thermal verdict for one subject at one moment.
type Assessment struct {
	Subject       string
	Temperature   float64 // after any cooling
	Grade         int     // 0..100, high is good
	Frequency     float64 // reports in the most recent bucket
	Acceleration  float64 // change in frequency over the last bucket
	Mean          float64 // mean per-bucket count over the window
	StdDev        float64 // standard deviation of per-bucket counts
	Settled       bool    // the burst has subsided (StdDev < Mean, or no reports)
	Escalation    string  // Stable | Elevated | Urgent
	ShouldPropose bool    // open a DAO suspension proposal now
	// RecommendedVoteWindow is how long a DAO vote should stay open: it shrinks
	// as temperature rises, so a hotter service gets a faster decision.
	RecommendedVoteWindow time.Duration
}

// Assess computes the thermal verdict for one subject from its report times.
func Assess(subject string, at []time.Time, now time.Time, p Params) Assessment {
	p = p.withDefaults()
	counts := bucketize(at, now, p)

	// Recency-weighted heat: the newest bucket (index Window-1) weighs 1, each
	// older bucket a further factor of Decay. Old reports fade, so temperature
	// decays on its own as a surge ages out.
	var heat float64
	for j, c := range counts {
		age := float64(len(counts) - 1 - j) // 0 = newest
		heat += float64(c) * math.Pow(p.Decay, age)
	}
	// Acceleration: a rising report rate adds heat beyond the raw frequency, so a
	// surge escalates faster than a flat line of the same height.
	freq := float64(counts[len(counts)-1])
	var prev float64
	if len(counts) >= 2 {
		prev = float64(counts[len(counts)-2])
	}
	accel := freq - prev
	if accel > 0 {
		heat += p.Accel * accel
	}

	mean, sd := meanStdDev(counts)
	settled := mean == 0 || sd < mean

	temp := heat
	if settled {
		temp *= p.CoolMul // the burst is over: cool back toward a good grade
	}

	grade := int(math.Round(100 * math.Exp(-temp/p.Scale)))
	if grade < 0 {
		grade = 0
	}
	if grade > 100 {
		grade = 100
	}

	a := Assessment{
		Subject: subject, Temperature: temp, Grade: grade,
		Frequency: freq, Acceleration: accel, Mean: mean, StdDev: sd, Settled: settled,
		Escalation: Stable, RecommendedVoteWindow: p.BaseVoteWindow,
	}
	if !settled && temp >= p.ProposeTemp {
		a.ShouldPropose = true
		a.Escalation = Elevated
		if temp >= p.UrgentTemp {
			a.Escalation = Urgent
		}
		// Accelerate: window = BaseVoteWindow * (ProposeTemp / temp), floored.
		scaled := time.Duration(float64(p.BaseVoteWindow) * (p.ProposeTemp / temp))
		if scaled < p.MinVoteWindow {
			scaled = p.MinVoteWindow
		}
		if scaled > p.BaseVoteWindow {
			scaled = p.BaseVoteWindow
		}
		a.RecommendedVoteWindow = scaled
	}
	return a
}

// AssessAll groups a mixed report stream by subject and assesses each.
func AssessAll(reports []Report, now time.Time, p Params) map[string]Assessment {
	bySubject := map[string][]time.Time{}
	for _, r := range reports {
		bySubject[r.Subject] = append(bySubject[r.Subject], r.At)
	}
	out := make(map[string]Assessment, len(bySubject))
	for subject, times := range bySubject {
		out[subject] = Assess(subject, times, now, p)
	}
	return out
}

// Grades extracts the address→grade map for a service-policy document.
func Grades(assessed map[string]Assessment) map[string]int {
	out := make(map[string]int, len(assessed))
	for subject, a := range assessed {
		out[subject] = a.Grade
	}
	return out
}

// ProposalCandidates returns the subjects that warrant a DAO suspension
// proposal now, hottest first, so a proposer acts on the most urgent first.
func ProposalCandidates(assessed map[string]Assessment) []Assessment {
	var out []Assessment
	for _, a := range assessed {
		if a.ShouldPropose {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Temperature != out[j].Temperature {
			return out[i].Temperature > out[j].Temperature
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// bucketize counts reports into p.Window trailing buckets ending at now,
// oldest first. Reports outside the window (or in the future) are ignored.
func bucketize(at []time.Time, now time.Time, p Params) []int {
	counts := make([]int, p.Window)
	bucketNs := p.Bucket.Nanoseconds()
	nowBucket := now.UnixNano() / bucketNs
	for _, t := range at {
		age := nowBucket - t.UnixNano()/bucketNs // 0 = same bucket as now
		if age < 0 || age >= int64(p.Window) {
			continue
		}
		counts[p.Window-1-int(age)]++
	}
	return counts
}

func meanStdDev(counts []int) (mean, sd float64) {
	n := float64(len(counts))
	if n == 0 {
		return 0, 0
	}
	var sum float64
	for _, c := range counts {
		sum += float64(c)
	}
	mean = sum / n
	var varc float64
	for _, c := range counts {
		d := float64(c) - mean
		varc += d * d
	}
	return mean, math.Sqrt(varc / n)
}
