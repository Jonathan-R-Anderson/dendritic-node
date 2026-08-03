package compute

// M3 — the local resource manager: whether to run work right now, and on how
// many cores.
//
// THE RULE EVERYTHING HERE FOLLOWS
// --------------------------------
// Bias every ambiguous decision toward the desktop user. Losing a work unit is
// cheap and recoverable — it is redundantly executed anyway (M5) and the
// scheduler will place it elsewhere. Losing the volunteer is neither: a node
// that stutters a game once gets uninstalled and does not come back.
//
// So every check below fails CLOSED. An unreadable sensor, an unparseable
// config, a signal that might mean the machine is in use — all of them stop
// work. The cost of being wrong in that direction is a few idle seconds. The
// cost of being wrong in the other direction is the machine.
//
// WHY CORES ARE RESERVED, NOT CAPPED
// ----------------------------------
// A utilisation cap ("use 50% of the CPU") still puts our threads on every
// core, competing with the desktop for each one. The scheduler then interleaves
// us with the compositor, the audio thread, and whatever the user is actually
// doing — which is felt as input lag and audio dropout even while the average
// looks polite.
//
// Reserving cores keeps whole cores untouched. Combined with idle scheduling
// priority, the desktop preempts rather than competes. This matters more for
// CPU than for GPU: a dropped frame is noticed and forgiven, a stuttering
// cursor is noticed and not.

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Policy is what the machine's owner opted into. Zero value is SAFE: disabled,
// nothing runs. Enabling is always an explicit act.
type Policy struct {
	Enabled bool `json:"enabled"`

	// ReserveCores are never taken, whatever else this says. Two by default:
	// one for whatever the user is doing and one for the system, which is the
	// difference between a machine that feels busy and one that feels broken.
	ReserveCores int `json:"reserve_cores"`

	// MaxCores caps what is offered after the reservation. 0 means "whatever
	// is left".
	MaxCores int `json:"max_cores"`

	// IdleOnly is the default and should stay it. Opting into always-on is a
	// decision for someone who knows their machine; it must never be what
	// happens to somebody who just installed the node.
	IdleOnly bool `json:"idle_only"`

	// IdleLoadPerCore is the run-queue depth per core above which the machine
	// counts as in use. 0 takes the default.
	IdleLoadPerCore float64 `json:"idle_load_per_core"`

	// Hours restricts work to a window, "22:00-07:00". Empty means any hour.
	// A window that wraps midnight is the normal case, not the exception.
	Hours string `json:"hours,omitempty"`

	// MaxTempC stops work when the hottest sensor exceeds it. 0 takes the
	// default; thermal protection is not opt-in.
	MaxTempC int `json:"max_temp_c"`

	// PauseOnBattery defaults ON via Normalise. Draining somebody's laptop for
	// a work unit is the single fastest way to get uninstalled.
	PauseOnBattery *bool `json:"pause_on_battery,omitempty"`

	// GPUBusyPercent is the utilisation above which the GPU counts as the
	// user's. Catches the case input-idleness misses entirely: a fullscreen
	// game leaves the keyboard untouched for minutes at a time.
	GPUBusyPercent int `json:"gpu_busy_percent"`

	// JobClasses this node will accept — "media", "index", "train", "infer",
	// "science". Empty means all. This is the governance lever from the
	// roadmap's threat 4: legal code, toxic purpose.
	JobClasses []string `json:"job_classes,omitempty"`
}

// Defaults chosen so an operator who enables the node and reads nothing else
// still gets a machine that stays pleasant to use.
const (
	defaultReserveCores    = 2
	defaultIdleLoadPerCore = 0.35
	defaultMaxTempC        = 82
	defaultGPUBusyPercent  = 20
)

// Normalise fills zero values with defaults and clamps nonsense.
//
// Note the direction of every clamp: toward doing less work. A policy that
// asks for a 200°C ceiling gets the default, not the request — a config typo
// must not be able to cook somebody's laptop.
func (p Policy) Normalise() Policy {
	if p.ReserveCores <= 0 {
		p.ReserveCores = defaultReserveCores
	}
	if p.IdleLoadPerCore <= 0 {
		p.IdleLoadPerCore = defaultIdleLoadPerCore
	}
	if p.MaxTempC <= 0 || p.MaxTempC > 100 {
		p.MaxTempC = defaultMaxTempC
	}
	if p.GPUBusyPercent <= 0 || p.GPUBusyPercent > 100 {
		p.GPUBusyPercent = defaultGPUBusyPercent
	}
	if p.PauseOnBattery == nil {
		on := true
		p.PauseOnBattery = &on
	}
	if !p.Enabled {
		// IdleOnly is meaningless while disabled, but normalising it here means
		// a policy printed to a log reads the way it will behave once enabled.
		p.IdleOnly = true
	}
	return p
}

// AcceptsClass reports whether this node will run a job of the given class.
func (p Policy) AcceptsClass(class string) bool {
	if len(p.JobClasses) == 0 {
		return true
	}
	for _, allowed := range p.JobClasses {
		if allowed == class {
			return true
		}
	}
	return false
}

// Sensors is what the governor reads. An interface so the decision logic can be
// tested against machine states that are hard to arrange on demand — a hot
// laptop on battery running a fullscreen game.
type Sensors interface {
	// LoadAverage1 is the 1-minute run-queue depth, or -1 if unreadable.
	LoadAverage1() float64
	// OnBattery reports discharging, and false when there is no battery.
	OnBattery() bool
	// HottestC is the highest thermal reading in Celsius, or -1 if unreadable.
	HottestC() int
	// GPUBusyPercent is 0-100, or -1 when no GPU exposes it.
	GPUBusyPercent() int
}

// Grant is the decision. Cores == 0 means "do not run", and Reason says why in
// words fit to show the machine's owner — "what is my node doing" deserves a
// sentence, not a log file.
type Grant struct {
	Cores  int    `json:"cores"`
	Reason string `json:"reason"`
}

// Allowed is a convenience for the common check.
func (g Grant) Allowed() bool { return g.Cores > 0 }

// Governor decides whether work may run.
type Governor struct {
	Policy  Policy
	Profile Profile
	Sensors Sensors
	// Now is injectable so the scheduled-hours window can be tested without
	// waiting for 3am.
	Now func() time.Time
}

// NewGovernor normalises the policy once, so every later Decide sees the same
// values and a log line printed at startup matches behaviour.
func NewGovernor(policy Policy, profile Profile, sensors Sensors) *Governor {
	return &Governor{
		Policy:  policy.Normalise(),
		Profile: profile,
		Sensors: sensors,
		Now:     time.Now,
	}
}

// Decide answers "may work run right now, and on how many cores".
//
// `running` is how many cores this node is ALREADY using, and passing it is not
// optional bookkeeping — it is what stops the governor oscillating. Load
// average includes our own work, so a node at its core limit sees a busy
// machine, stops, watches load fall, starts, and repeats. Subtracting our own
// contribution asks the question that actually matters: is anyone ELSE using
// this machine.
func (g *Governor) Decide(running int) Grant {
	policy := g.Policy
	if !policy.Enabled {
		return Grant{0, "compute is switched off for this node"}
	}

	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	if within, err := withinHours(policy.Hours, now()); err != nil {
		// An unparseable window is not permission to run at any hour. It is a
		// config the operator meant to restrict something with.
		return Grant{0, "scheduled hours could not be read (" + err.Error() + "), so nothing runs"}
	} else if !within {
		return Grant{0, "outside the hours this node accepts work (" + policy.Hours + ")"}
	}

	if g.Sensors == nil {
		return Grant{0, "no way to tell whether this machine is in use"}
	}

	if *policy.PauseOnBattery && g.Sensors.OnBattery() {
		return Grant{0, "running on battery"}
	}

	temp := g.Sensors.HottestC()
	if temp < 0 {
		// Unreadable thermals are common in containers and VMs, where there is
		// also no fan to save. Not a reason to refuse work — but it IS a reason
		// not to pretend the ceiling is being enforced.
		temp = 0
	}
	if temp >= policy.MaxTempC {
		return Grant{0, fmt.Sprintf("too hot (%d°C, limit %d°C)", temp, policy.MaxTempC)}
	}

	cores := policy.MaxCores
	available := g.Profile.CPU.PhysicalCores - policy.ReserveCores
	if available < 0 {
		available = 0
	}
	if cores <= 0 || cores > available {
		cores = available
	}
	if cores <= 0 {
		return Grant{0, fmt.Sprintf("no cores to spare (%d physical, %d reserved for you)",
			g.Profile.CPU.PhysicalCores, policy.ReserveCores)}
	}

	if policy.IdleOnly {
		load := g.Sensors.LoadAverage1()
		if load < 0 {
			return Grant{0, "cannot read system load, so cannot tell if you are using this machine"}
		}
		// Our own threads are on that run queue. Without subtracting them the
		// governor would read its own work as the user's and stop.
		others := load - float64(running)
		if others < 0 {
			others = 0
		}
		perCore := others / float64(max(g.Profile.CPU.LogicalCores, 1))
		if perCore > policy.IdleLoadPerCore {
			return Grant{0, fmt.Sprintf("machine is in use (load %.2f across %d threads)",
				others, g.Profile.CPU.LogicalCores)}
		}

		if busy := g.Sensors.GPUBusyPercent(); busy > policy.GPUBusyPercent {
			// The case input-idleness misses completely. Somebody four hours
			// into a fullscreen game has touched no key for minutes, and their
			// machine is as in-use as it ever gets.
			return Grant{0, fmt.Sprintf("GPU is busy (%d%%), so something is running", busy)}
		}
	}

	return Grant{cores, fmt.Sprintf("%d of %d cores, %d reserved for you",
		cores, g.Profile.CPU.PhysicalCores, policy.ReserveCores)}
}

// withinHours reports whether now falls inside "HH:MM-HH:MM".
//
// A window that wraps midnight ("22:00-07:00") is the normal case for this
// feature, not an edge case — people offer their machines overnight. Handling
// it as an afterthought is how such a window silently becomes "never".
func withinHours(window string, now time.Time) (bool, error) {
	window = strings.TrimSpace(window)
	if window == "" {
		return true, nil
	}
	startText, endText, ok := strings.Cut(window, "-")
	if !ok {
		return false, fmt.Errorf("expected HH:MM-HH:MM, got %q", window)
	}
	start, err := parseClock(startText)
	if err != nil {
		return false, err
	}
	end, err := parseClock(endText)
	if err != nil {
		return false, err
	}
	minutes := now.Hour()*60 + now.Minute()
	if start == end {
		// Not "always" and not "never" — an ambiguous window, so it stops work
		// like every other ambiguity here.
		return false, fmt.Errorf("start and end are the same time (%q)", window)
	}
	if start < end {
		return minutes >= start && minutes < end, nil
	}
	return minutes >= start || minutes < end, nil
}

func parseClock(text string) (int, error) {
	text = strings.TrimSpace(text)
	hourText, minuteText, ok := strings.Cut(text, ":")
	if !ok {
		return 0, fmt.Errorf("expected HH:MM, got %q", text)
	}
	hour, err := strconv.Atoi(strings.TrimSpace(hourText))
	if err != nil || hour < 0 || hour > 23 {
		return 0, fmt.Errorf("bad hour in %q", text)
	}
	minute, err := strconv.Atoi(strings.TrimSpace(minuteText))
	if err != nil || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("bad minute in %q", text)
	}
	return hour*60 + minute, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
