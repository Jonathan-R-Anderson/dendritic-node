package swarmscore

import (
	"testing"
	"time"
)

// midBucketNow is a now that sits in the middle of an hour bucket, so reports
// placed k whole buckets earlier land cleanly k buckets back.
var midBucketNow = time.Unix(3_600_000_000+1800, 0)

func testParams() Params { return Params{Bucket: time.Hour, Window: 8} }

// times turns a per-bucket plan (index 0 oldest-in-window, last newest) into
// report timestamps. The plan length must be <= Window.
func times(now time.Time, p Params, perBucket []int) []time.Time {
	var out []time.Time
	n := len(perBucket)
	for j, c := range perBucket {
		age := n - 1 - j
		t := now.Add(-time.Duration(age) * p.Bucket)
		for i := 0; i < c; i++ {
			out = append(out, t)
		}
	}
	return out
}

func TestColdServiceIsGradeA(t *testing.T) {
	a := Assess("svc", nil, midBucketNow, testParams())
	if a.Grade != 100 {
		t.Fatalf("no reports should grade 100, got %d", a.Grade)
	}
	if !a.Settled || a.ShouldPropose || a.Escalation != Stable {
		t.Fatalf("cold service not stable: %+v", a)
	}
}

// The headline rule: equal report VOLUME, opposite outcome by variance. A burst
// (high stddev) stays hot and bad; a steady stream (stddev < mean) cools to a
// good grade.
func TestBurstyIsHotSteadyIsCool(t *testing.T) {
	p := testParams()
	bursty := Assess("b", times(midBucketNow, p, []int{0, 0, 0, 0, 0, 0, 0, 16}), midBucketNow, p)
	steady := Assess("s", times(midBucketNow, p, []int{2, 2, 2, 2, 2, 2, 2, 2}), midBucketNow, p)

	if bursty.Settled {
		t.Fatal("a fresh burst should not read as settled")
	}
	if !steady.Settled {
		t.Fatalf("a steady low-variance stream should settle: sd=%.2f mean=%.2f", steady.StdDev, steady.Mean)
	}
	if bursty.Grade >= steady.Grade {
		t.Fatalf("bursty grade %d should be worse than steady grade %d", bursty.Grade, steady.Grade)
	}
	if bursty.Grade > 30 {
		t.Fatalf("a hot burst should grade poorly, got %d", bursty.Grade)
	}
	if steady.Grade < 70 {
		t.Fatalf("a settled stream should grade well, got %d", steady.Grade)
	}
	if !bursty.ShouldPropose || bursty.Escalation != Urgent {
		t.Fatalf("a hot burst should escalate urgently: %+v", bursty)
	}
	if steady.ShouldPropose {
		t.Fatal("a settled service should not trigger a DAO proposal")
	}
}

// Acceleration heats faster: two services with the SAME total and same newest
// frequency, but one arriving as a rising spike, the other flat.
func TestAccelerationHeatsFaster(t *testing.T) {
	p := testParams()
	flat := Assess("f", times(midBucketNow, p, []int{0, 0, 0, 0, 0, 0, 4, 4}), midBucketNow, p)  // accel 0, total 8
	spike := Assess("k", times(midBucketNow, p, []int{0, 0, 0, 0, 0, 0, 0, 8}), midBucketNow, p) // accel +8, total 8

	if spike.Temperature <= flat.Temperature {
		t.Fatalf("a rising spike should be hotter than a flat line of equal volume: spike=%.2f flat=%.2f",
			spike.Temperature, flat.Temperature)
	}
	if spike.Acceleration <= 0 {
		t.Fatalf("spike acceleration should be positive, got %.2f", spike.Acceleration)
	}
}

// Cooling: as a burst ages out of the trailing window, the grade recovers, and
// once it is entirely out the service is settled at grade 100.
func TestCoolingReturnsToGoodGradeAsBurstAges(t *testing.T) {
	p := testParams()
	burst := times(midBucketNow, p, []int{0, 0, 0, 0, 0, 0, 0, 16})

	hot := Assess("x", burst, midBucketNow, p)
	mid := Assess("x", burst, midBucketNow.Add(4*p.Bucket), p)  // burst now 4 buckets old
	aged := Assess("x", burst, midBucketNow.Add(8*p.Bucket), p) // burst fully out of the window

	if !(hot.Grade < mid.Grade && mid.Grade < aged.Grade) {
		t.Fatalf("grade should recover as the burst ages: hot=%d mid=%d aged=%d",
			hot.Grade, mid.Grade, aged.Grade)
	}
	if aged.Grade != 100 || !aged.Settled {
		t.Fatalf("fully-aged burst should be settled at grade 100, got grade=%d settled=%v",
			aged.Grade, aged.Settled)
	}
}

// The DAO vote is accelerated as temperature climbs: a hotter service gets a
// shorter recommended voting window, floored at MinVoteWindow.
func TestVoteWindowShrinksWithTemperature(t *testing.T) {
	p := testParams().withDefaults()
	milder := Assess("m", times(midBucketNow, p, []int{0, 0, 0, 0, 0, 0, 0, 8}), midBucketNow, p)
	hotter := Assess("h", times(midBucketNow, p, []int{0, 0, 0, 0, 0, 0, 0, 60}), midBucketNow, p)

	if !milder.ShouldPropose || !hotter.ShouldPropose {
		t.Fatalf("both should propose: milder=%v hotter=%v", milder.ShouldPropose, hotter.ShouldPropose)
	}
	if hotter.RecommendedVoteWindow >= milder.RecommendedVoteWindow {
		t.Fatalf("hotter service should get a shorter vote window: hot=%s mild=%s",
			hotter.RecommendedVoteWindow, milder.RecommendedVoteWindow)
	}
	if hotter.RecommendedVoteWindow < p.MinVoteWindow {
		t.Fatalf("vote window fell below the floor: %s < %s", hotter.RecommendedVoteWindow, p.MinVoteWindow)
	}
}

func TestDeterministic(t *testing.T) {
	p := testParams()
	reports := times(midBucketNow, p, []int{0, 1, 0, 3, 0, 5, 2, 9})
	a := Assess("d", reports, midBucketNow, p)
	b := Assess("d", reports, midBucketNow, p)
	if a != b {
		t.Fatalf("Assess is not deterministic:\n%+v\n%+v", a, b)
	}
}

func TestAssessAllGradesAndCandidates(t *testing.T) {
	p := testParams()
	var reports []Report
	for _, ts := range times(midBucketNow, p, []int{0, 0, 0, 0, 0, 0, 0, 40}) {
		reports = append(reports, Report{Subject: "hot", At: ts})
	}
	for _, ts := range times(midBucketNow, p, []int{1, 1, 1, 1, 1, 1, 1, 1}) {
		reports = append(reports, Report{Subject: "calm", At: ts})
	}
	assessed := AssessAll(reports, midBucketNow, p)
	if len(assessed) != 2 {
		t.Fatalf("expected two subjects, got %d", len(assessed))
	}
	grades := Grades(assessed)
	if grades["hot"] >= grades["calm"] {
		t.Fatalf("hot should grade worse than calm: %d vs %d", grades["hot"], grades["calm"])
	}
	cands := ProposalCandidates(assessed)
	if len(cands) != 1 || cands[0].Subject != "hot" {
		t.Fatalf("only the hot service should be a proposal candidate, got %+v", cands)
	}
}
