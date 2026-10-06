#!/usr/bin/env bash
# Direct wallet deployment: no factory or helper contract may capture the beneficiary.
set -euo pipefail
: "${RPC_URL:?set the target chain RPC URL}"
: "${ACCOUNT:?set a Foundry keystore account}"
: "${DEPLOYER:?set the expected deploying wallet / immutable beneficiary address}"
: "${REGISTRATION_FEE_WEI:?set explicitly, including 0}"
: "${RECORD_FEE_WEI:?set explicitly, including 0}"
: "${TRANSFER_FEE_WEI:?set explicitly, including 0}"
# TLD governance: the DAO vote token (an ERC-20 whose balanceOf is the vote weight),
# the voting period in seconds, and the quorum in vote-token units. VOTE_TOKEN=0x0
# disables the DAO path entirely (only ICANN-marked suffixes can then be enabled).
: "${VOTE_TOKEN:?set the DAO vote-token address, or 0x0000000000000000000000000000000000000000 to disable governance}"
: "${VOTING_PERIOD_SECONDS:?set explicitly, including 0}"
: "${QUORUM_VOTES:?set explicitly, including 0}"
for fee in "$REGISTRATION_FEE_WEI" "$RECORD_FEE_WEI" "$TRANSFER_FEE_WEI" "$VOTING_PERIOD_SECONDS" "$QUORUM_VOTES"; do
  [[ "$fee" =~ ^[0-9]+$ ]] || { echo 'Fees/period/quorum must be nonnegative integers' >&2; exit 1; }
done
[[ "$VOTE_TOKEN" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo 'VOTE_TOKEN must be a 20-byte address' >&2; exit 1; }
wallet=$(cast wallet address --account "$ACCOUNT")
[[ "${wallet,,}" == "${DEPLOYER,,}" ]] || { echo 'Keystore address differs from DEPLOYER' >&2; exit 1; }
printf 'Initial administrator and permanent beneficiary: %s\n' "$wallet"
cd "$(dirname "$0")/.."
args=()
if [[ "${1:-}" == '--broadcast' ]]; then args+=(--broadcast);
elif [[ -n "${1:-}" ]]; then echo 'Usage: deploy.sh [--broadcast]' >&2; exit 1; fi
forge create src/AxonTLD.sol:AxonTLD --rpc-url "$RPC_URL" --account "$ACCOUNT" \
  "${args[@]}" --constructor-args "$REGISTRATION_FEE_WEI" "$RECORD_FEE_WEI" "$TRANSFER_FEE_WEI" \
  "$VOTE_TOKEN" "$VOTING_PERIOD_SECONDS" "$QUORUM_VOTES"
