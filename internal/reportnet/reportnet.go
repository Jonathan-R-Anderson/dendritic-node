// Package reportnet propagates content reports (dht.ContentReport, §89) across
// the network and turns a subject's reports into a swarm-temperature grade.
//
// A report is a public, attributed PUBLICATION, not a submission to a server —
// so it has to reach every node that grades, with no central collector. This
// carries it over the same Kademlia-over-AXON provider substrate that mirror
// discovery and the DCS worker registry already use: each reporter PUTs its
// signed report under a per-(subject, reporter) key and PROVIDEs a per-subject
// rendezvous, and any node enumerates every report about a subject with one
// lookup. Reporting is attributed by construction (§89 states this cost
// plainly): the reporter is the node's own identity, bound into the key.
//
// The grade is NOT computed here — swarmscore owns the thermal model. This
// package is the pipe (publish/find) plus the adapter that feeds the reports it
// finds into swarmscore.
package reportnet

import (
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/dht"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/swarmscore"
)

// DHTReportNamespace is the DHT key namespace for content-report records.
const DHTReportNamespace = "rabbiit-report"

// MaxReportValue caps a stored report; a report is pointers + bounded text, not
// a payload channel (§89).
const MaxReportValue = 8 << 10

// SubjectTag is the per-subject key/rendezvous component: the hex of the
// 32-byte subject hash a report accumulates against.
func SubjectTag(nameHash []byte) string { return hex.EncodeToString(nameHash) }

// ReportDHTKey is where one reporter's report about one subject is stored: one
// key per (subject, reporter node), so a reporter is the single writer of its
// own report and a repeat rewrites it rather than flooding the neighbourhood.
func ReportDHTKey(nameHash []byte, nodeID string) string {
	return "/" + DHTReportNamespace + "/" + SubjectTag(nameHash) + "/" + nodeID
}

// RendezvousLabel is the fixed label whose hash is the per-subject rendezvous
// every reporter of that subject provides, so any node finds them all at once.
func RendezvousLabel(nameHash []byte) string {
	return "rabbiit-report-rendezvous/1:" + SubjectTag(nameHash)
}

func splitKey(key string) (tag, nodeID string, ok bool) {
	prefix := "/" + DHTReportNamespace + "/"
	if !strings.HasPrefix(key, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(key, prefix)
	slash := strings.LastIndex(rest, "/")
	if slash <= 0 || slash == len(rest)-1 {
		return "", "", false
	}
	return rest[:slash], rest[slash+1:], true
}

// DHTValidator validates and selects content-report records in the DHT. A
// record is valid only if it decodes, is stored under a key matching its own
// subject and reporter, is signed by that reporter (dht.ValidateReport), binds
// to the node id in the key, and is unexpired. Select prefers the highest
// sequence, so a reporter's correction wins over the version it replaced.
type DHTValidator struct{ Now func() time.Time }

func (v DHTValidator) Validate(key string, value []byte) error {
	tag, nodeID, ok := splitKey(key)
	if !ok {
		return errors.New("reportnet: invalid report DHT key")
	}
	if len(value) > MaxReportValue {
		return errors.New("reportnet: report record too large")
	}
	rec, err := dht.DecodeRecord(dht.ClassReport, value)
	if err != nil {
		return errors.New("reportnet: invalid report encoding")
	}
	cr, ok := rec.(*dht.ContentReport)
	if !ok {
		return errors.New("reportnet: record is not a content report")
	}
	if SubjectTag(cr.NameHash) != tag {
		return errors.New("reportnet: report subject does not match its key")
	}
	// The reporter is the node that stored it: bind the ed25519 reporter key to
	// the peer id in the key, so a peer cannot store a report under another
	// node's slot.
	pk, err := crypto.UnmarshalEd25519PublicKey(cr.Reporter)
	if err != nil {
		return errors.New("reportnet: invalid reporter key")
	}
	pid, err := peer.IDFromPublicKey(pk)
	if err != nil || pid.String() != nodeID {
		return errors.New("reportnet: reporter does not match the node id in the key")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if cr.ExpiresAt != 0 && cr.ExpiresAt <= now.Unix() {
		return errors.New("reportnet: report expired")
	}
	return dht.ValidateReport(cr)
}

func (v DHTValidator) Select(_ string, values [][]byte) (int, error) {
	best, bestSeq := -1, uint64(0)
	for i, value := range values {
		rec, err := dht.DecodeRecord(dht.ClassReport, value)
		if err != nil {
			continue
		}
		cr, ok := rec.(*dht.ContentReport)
		if !ok {
			continue
		}
		if best == -1 || cr.Sequence > bestSeq {
			best, bestSeq = i, cr.Sequence
		}
	}
	if best < 0 {
		return 0, errors.New("reportnet: no valid report records")
	}
	return best, nil
}

// ToSwarmReports turns found content reports into the report stream swarmscore
// grades: one event per report, its subject the hex of the report's subject
// hash, its time the report's issue time. A reporter filing repeatedly is one
// record (same key), so this counts distinct reporters over time — which is the
// frequency the thermal model is meant to read.
func ToSwarmReports(reports []*dht.ContentReport) []swarmscore.Report {
	out := make([]swarmscore.Report, 0, len(reports))
	for _, r := range reports {
		if r == nil || len(r.NameHash) == 0 {
			continue
		}
		out = append(out, swarmscore.Report{
			Subject: SubjectTag(r.NameHash),
			At:      time.Unix(r.IssuedAt, 0),
		})
	}
	return out
}
