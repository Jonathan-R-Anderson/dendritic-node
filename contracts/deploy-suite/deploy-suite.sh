#!/usr/bin/env bash
# Deploy the dendritic network's full smart-contract suite (14 contracts) in
# dependency order to $RPC with $KEY, printing the gas each deployment used and
# the total. Point RPC/KEY/OWNER at the target chain to launch for real.
#
# SETUP (one time): this is a Foundry project. Vendor OpenZeppelin v5 and gather
# the sources next to it:
#   git clone --depth 1 --branch v5.1.0 https://github.com/OpenZeppelin/openzeppelin-contracts lib/openzeppelin-contracts
#   mkdir -p src && cp ../../../../dendritic/proof-of-facilitation/contracts/*.sol src/   # the PoF suite (sibling repo)
#   cp ../tld/src/AxonTLD.sol src/                                                         # this repo's AxonTLD
#   # foundry.toml must set: remappings = ["@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/"], solc 0.8.24
#   forge build
#
# USAGE:
#   RPC=<rpc-url> KEY=<deployer-privkey> OWNER=<deployer-address> ./deploy-suite.sh
#
# The constructor arguments below are PLACEHOLDERS chosen to deploy successfully so
# the gas is measured accurately. FOR A REAL LAUNCH replace them with production
# values: a real governor/guardian multisig, the fee schedule you want, the
# canonical `.axon` TLD node hash, real term/price/bond parameters, etc. Then run
# the sibling's Hardhat role-wiring (deploy/00_phase0 -> 01_phase1 -> 02_channels)
# and the AxonToken genesis mint. Reads are free; only these deploy+wire txs cost gas.
set -u
export PATH="$HOME/.foundry/bin:$PATH"
RPC="${RPC:-http://127.0.0.1:8601}"
KEY="${KEY:?set KEY to the deployer private key}"
OWNER="${OWNER:?set OWNER to the deployer / initial-admin address}"
B32=0x1111111111111111111111111111111111111111111111111111111111111111   # placeholder bytes32 (tldNode / schema)
TOTAL=0
declare -A ADDR
NOW=$(cast block latest --rpc-url "$RPC" --field timestamp 2>/dev/null); NOW=${NOW:-$(date +%s)}
GUARDIAN_EXPIRES=$((NOW + 2592000))   # +30 days (TLDRegistry requires a bounded, near-future guardian expiry)

dep() { # $1 Name   $2.. constructor-arg values
  local name="$1"; shift
  local out addr hash gas
  out=$(forge create "src/$name.sol:$name" --rpc-url "$RPC" --private-key "$KEY" --broadcast \
        ${@:+--constructor-args "$@"} 2>&1)
  addr=$(echo "$out" | grep -oE 'Deployed to: 0x[0-9a-fA-F]{40}' | grep -oE '0x[0-9a-fA-F]{40}')
  hash=$(echo "$out" | grep -oE 'Transaction hash: 0x[0-9a-fA-F]{64}' | grep -oE '0x[0-9a-fA-F]{64}')
  if [ -z "$addr" ]; then echo "  !! $name FAILED: $(echo "$out" | tail -2 | tr '\n' ' ')"; return 1; fi
  gas=$(cast receipt "$hash" --rpc-url "$RPC" 2>/dev/null | awk '/^gasUsed/{print $2}'); gas=${gas:-0}
  TOTAL=$((TOTAL+gas)); ADDR[$name]=$addr
  printf "  %-22s %s  gas=%'d\n" "$name" "$addr" "$gas"
}

echo "Deploying the dendritic suite to $RPC (owner $OWNER) ..."
dep AxonToken "$OWNER"
dep NodeRegistry "$OWNER"
dep EpochManager "$OWNER" 86400
dep StakeVault "$OWNER" "${ADDR[AxonToken]}" 86400
dep RewardDistributor "$OWNER" "${ADDR[AxonToken]}" "${ADDR[EpochManager]}"
dep DisputeManager "$OWNER" "${ADDR[AxonToken]}" "${ADDR[EpochManager]}" "${ADDR[StakeVault]}" 100000000000000000000
dep ServicePolicyRegistry "$OWNER"
dep AxonChannels "${ADDR[AxonToken]}" 86400
dep SettlementKeeper "$OWNER" "${ADDR[EpochManager]}" 1000000000000000
dep Treasury "$OWNER" "${ADDR[AxonToken]}" "${ADDR[EpochManager]}" "${ADDR[RewardDistributor]}" 1000000000000000000000 1000000000000000000000000000
dep AxonGovernance "$OWNER" 86400 6000 1000000000000000000000 5000
dep AxonRegistry "$OWNER" "${ADDR[AxonToken]}" "${ADDR[Treasury]}" "$B32" "[86400,60,86400,31536000,86400,86400]" "[10000000000000000,1000000000000000000]" "[100,3,10]" 86400
dep TLDRegistry "$OWNER" "$OWNER" "$GUARDIAN_EXPIRES" "${ADDR[AxonToken]}" "${ADDR[Treasury]}" 1000000000000000000 "$B32"
dep AxonTLD 1000000000000000 100000000000000 1000000000000000 "${ADDR[AxonToken]}" 86400 1000000000000000000000

echo "-----------------------------------------------------------"
printf "TOTAL DEPLOYMENT GAS: %'d\n" "$TOTAL"
