package ethproof

// The beacon API client, for live mainnet validation — roadmap P12-5.9.
//
// SEPARATE FROM THE EXECUTION RPC, DELIBERATELY
// ---------------------------------------------
// This talks to a consensus node. The execution RPC in client.go talks to an
// execution node. They must not be the same provider, and nothing here reads
// the execution endpoint's configuration — because the whole point of the live
// validation is:
//
//	independent anchor  ->  provider data  ->  cryptographic verification
//
// rather than:
//
//	provider  ->  checkpoint  ->  provider
//
// The consensus data is what AUTHENTICATES; the execution data is what gets
// CHECKED. One provider supplying both would leave nothing being verified
// against anything.
//
// WHAT THIS DOES NOT DO
// ---------------------
// It does not decide anything. Every response is a candidate handed to the
// light client, which accepts or refuses it. A beacon node that lied would
// produce updates whose signatures do not verify under the anchored committee,
// which is the same rejection an offline node produces — no answer.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// BeaconClient reads the consensus layer's light client REST namespace.
type BeaconClient struct {
	Endpoint string
	HTTP     *http.Client
}

// NewBeaconClient builds one.
func NewBeaconClient(endpoint string) *BeaconClient {
	return &BeaconClient{
		Endpoint: strings.TrimRight(endpoint, "/"),
		HTTP:     &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *BeaconClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("beacon: %s returned %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Genesis is the chain's identity, used to check the compiled-in constant
// against the node a deployment will actually follow.
type Genesis struct {
	GenesisValidatorsRoot string `json:"genesis_validators_root"`
	GenesisForkVersion    string `json:"genesis_fork_version"`
	GenesisTime           string `json:"genesis_time"`
}

// Genesis fetches the chain identity.
func (c *BeaconClient) Genesis(ctx context.Context) (Genesis, error) {
	var wrapper struct {
		Data Genesis `json:"data"`
	}
	err := c.get(ctx, "/eth/v1/beacon/genesis", &wrapper)
	return wrapper.Data, err
}

// jsonHeader is the beacon API's rendering of a BeaconBlockHeader.
type jsonHeader struct {
	Slot          string `json:"slot"`
	ProposerIndex string `json:"proposer_index"`
	ParentRoot    string `json:"parent_root"`
	StateRoot     string `json:"state_root"`
	BodyRoot      string `json:"body_root"`
}

func (j jsonHeader) decode() (BeaconBlockHeader, error) {
	var out BeaconBlockHeader
	slot, err := strconv.ParseUint(j.Slot, 10, 64)
	if err != nil {
		return out, fmt.Errorf("beacon: slot %q: %w", j.Slot, err)
	}
	proposer, err := strconv.ParseUint(j.ProposerIndex, 10, 64)
	if err != nil {
		return out, fmt.Errorf("beacon: proposer_index %q: %w", j.ProposerIndex, err)
	}
	out.Slot, out.ProposerIndex = slot, proposer
	for _, f := range []struct {
		src string
		dst *Root
	}{{j.ParentRoot, &out.ParentRoot}, {j.StateRoot, &out.StateRoot}, {j.BodyRoot, &out.BodyRoot}} {
		r, err := decodeHex32(f.src)
		if err != nil {
			return out, err
		}
		*f.dst = r
	}
	return out, nil
}

// jsonCommittee is the beacon API's rendering of a SyncCommittee.
type jsonCommittee struct {
	Pubkeys         []string `json:"pubkeys"`
	AggregatePubkey string   `json:"aggregate_pubkey"`
}

func (j jsonCommittee) decode() (*SyncCommittee, error) {
	out := &SyncCommittee{Pubkeys: make([][]byte, 0, len(j.Pubkeys))}
	for i, k := range j.Pubkeys {
		raw, err := hex.DecodeString(strings.TrimPrefix(k, "0x"))
		if err != nil {
			return nil, fmt.Errorf("beacon: pubkey %d: %w", i, err)
		}
		out.Pubkeys = append(out.Pubkeys, raw)
	}
	agg, err := hex.DecodeString(strings.TrimPrefix(j.AggregatePubkey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("beacon: aggregate pubkey: %w", err)
	}
	out.AggregatePubkey = agg
	return out, nil
}

func decodeBranch(hexes []string) ([]Root, error) {
	out := make([]Root, 0, len(hexes))
	for i, h := range hexes {
		r, err := decodeHex32(h)
		if err != nil {
			return nil, fmt.Errorf("beacon: branch node %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Bootstrap is the light client's starting point for a checkpoint.
//
// The committee it carries is checked against the checkpoint's committee root
// by the caller — never adopted because the node supplied it.
type Bootstrap struct {
	Header                     BeaconBlockHeader
	CurrentSyncCommittee       *SyncCommittee
	CurrentSyncCommitteeBranch []Root
}

// Bootstrap fetches the light client bootstrap for a trusted block root.
func (c *BeaconClient) Bootstrap(ctx context.Context, blockRoot string) (Bootstrap, error) {
	var wrapper struct {
		Data struct {
			Header struct {
				Beacon jsonHeader `json:"beacon"`
			} `json:"header"`
			CurrentSyncCommittee       jsonCommittee `json:"current_sync_committee"`
			CurrentSyncCommitteeBranch []string      `json:"current_sync_committee_branch"`
		} `json:"data"`
	}
	if err := c.get(ctx,
		"/eth/v1/beacon/light_client/bootstrap/"+blockRoot, &wrapper); err != nil {
		return Bootstrap{}, err
	}
	header, err := wrapper.Data.Header.Beacon.decode()
	if err != nil {
		return Bootstrap{}, err
	}
	committee, err := wrapper.Data.CurrentSyncCommittee.decode()
	if err != nil {
		return Bootstrap{}, err
	}
	branch, err := decodeBranch(wrapper.Data.CurrentSyncCommitteeBranch)
	if err != nil {
		return Bootstrap{}, err
	}
	return Bootstrap{Header: header, CurrentSyncCommittee: committee,
		CurrentSyncCommitteeBranch: branch}, nil
}

// jsonUpdate is the shared shape of light client updates.
type jsonUpdate struct {
	AttestedHeader struct {
		Beacon    jsonHeader `json:"beacon"`
		Execution *struct {
			ParentHash    string `json:"parent_hash"`
			FeeRecipient  string `json:"fee_recipient"`
			StateRoot     string `json:"state_root"`
			ReceiptsRoot  string `json:"receipts_root"`
			LogsBloom     string `json:"logs_bloom"`
			PrevRandao    string `json:"prev_randao"`
			BlockNumber   string `json:"block_number"`
			GasLimit      string `json:"gas_limit"`
			GasUsed       string `json:"gas_used"`
			Timestamp     string `json:"timestamp"`
			ExtraData     string `json:"extra_data"`
			BaseFeePerGas string `json:"base_fee_per_gas"`
			BlockHash     string `json:"block_hash"`
			TxRoot        string `json:"transactions_root"`
			Withdrawals   string `json:"withdrawals_root"`
			BlobGasUsed   string `json:"blob_gas_used"`
			ExcessBlobGas string `json:"excess_blob_gas"`
		} `json:"execution"`
		ExecutionBranch []string `json:"execution_branch"`
	} `json:"attested_header"`
	NextSyncCommittee       *jsonCommittee `json:"next_sync_committee"`
	NextSyncCommitteeBranch []string       `json:"next_sync_committee_branch"`
	FinalizedHeader         *struct {
		Beacon          jsonHeader `json:"beacon"`
		Execution       *json.RawMessage `json:"execution"`
		ExecutionBranch []string         `json:"execution_branch"`
	} `json:"finalized_header"`
	FinalityBranch []string `json:"finality_branch"`
	SyncAggregate  struct {
		SyncCommitteeBits      string `json:"sync_committee_bits"`
		SyncCommitteeSignature string `json:"sync_committee_signature"`
	} `json:"sync_aggregate"`
	SignatureSlot string `json:"signature_slot"`
}

func (j jsonUpdate) decode() (*Update, error) {
	attested, err := j.AttestedHeader.Beacon.decode()
	if err != nil {
		return nil, err
	}
	u := &Update{AttestedHeader: attested}

	if j.FinalizedHeader != nil {
		finalized, err := j.FinalizedHeader.Beacon.decode()
		if err != nil {
			return nil, err
		}
		u.FinalizedHeader = finalized
	}
	if u.FinalityBranch, err = decodeBranch(j.FinalityBranch); err != nil {
		return nil, err
	}
	if j.NextSyncCommittee != nil {
		if u.NextCommittee, err = j.NextSyncCommittee.decode(); err != nil {
			return nil, err
		}
		if u.NextCommitteeBranch, err = decodeBranch(j.NextSyncCommitteeBranch); err != nil {
			return nil, err
		}
	}

	bits, err := hex.DecodeString(strings.TrimPrefix(j.SyncAggregate.SyncCommitteeBits, "0x"))
	if err != nil {
		return nil, fmt.Errorf("beacon: sync committee bits: %w", err)
	}
	u.Participation = Participation(bits)

	sig, err := hex.DecodeString(strings.TrimPrefix(j.SyncAggregate.SyncCommitteeSignature, "0x"))
	if err != nil {
		return nil, fmt.Errorf("beacon: sync committee signature: %w", err)
	}
	u.Signature = sig

	if u.SignatureSlot, err = strconv.ParseUint(j.SignatureSlot, 10, 64); err != nil {
		return nil, fmt.Errorf("beacon: signature_slot %q: %w", j.SignatureSlot, err)
	}
	return u, nil
}

// Updates fetches sync committee updates for a range of periods.
func (c *BeaconClient) Updates(ctx context.Context, startPeriod, count uint64) ([]*Update, error) {
	var wrapper []struct {
		Data jsonUpdate `json:"data"`
	}
	path := fmt.Sprintf("/eth/v1/beacon/light_client/updates?start_period=%d&count=%d",
		startPeriod, count)
	if err := c.get(ctx, path, &wrapper); err != nil {
		return nil, err
	}
	out := make([]*Update, 0, len(wrapper))
	for i := range wrapper {
		u, err := wrapper[i].Data.decode()
		if err != nil {
			return nil, fmt.Errorf("beacon: update %d: %w", i, err)
		}
		out = append(out, u)
	}
	return out, nil
}

// FinalityUpdate fetches the newest finality update.
func (c *BeaconClient) FinalityUpdate(ctx context.Context) (*Update, error) {
	var wrapper struct {
		Data jsonUpdate `json:"data"`
	}
	if err := c.get(ctx, "/eth/v1/beacon/light_client/finality_update", &wrapper); err != nil {
		return nil, err
	}
	return wrapper.Data.decode()
}
