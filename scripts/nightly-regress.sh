#!/usr/bin/env bash
# G0.30k: the nightly regression run. The labs that run without root (the
# DNS lab in a user namespace: qps, hostile, ops), their numbers in one
# metrics.jsonl, compared with the last green night of the history by
# `cargo xtask nightly compare` (margin per metric from the noise between
# green nights). Run by the `regression` job of .github/workflows/nightly.yml
# on the self-hosted runner; by hand on a host to try it:
#
#   scripts/nightly-regress.sh --history <dir> --out <dir> [--duration <s>]
#       [--tests qps,hostile,ops] [--tools <dir>]
#
# Writes <out>/metrics.jsonl, <out>/report.md, <out>/commits.txt (since the
# last green night) and <out>/verdict: ok, regressed or broken (a lab
# failed: no comparison). Never writes the history: the job does, once it
# knows the verdict. Exit 0 unless the arguments are wrong.
set -euo pipefail
export LC_ALL=C
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
HISTORY="" OUT="" DUR=10 TESTS=qps,hostile,ops TOOLS=""
while [ $# -gt 0 ]; do
	case $1 in
	--history) HISTORY=$2; shift 2 ;;
	--out) OUT=$2; shift 2 ;;
	--duration) DUR=$2; shift 2 ;;
	--tests) TESTS=$2; shift 2 ;;
	--tools) TOOLS=$2; shift 2 ;;
	*) echo "usage: $0 --history <dir> --out <dir> [--duration <s>] [--tests a,b] [--tools <dir>]"; exit 2 ;;
	esac
done
[ -n "$HISTORY" ] && [ -n "$OUT" ] || { echo "--history and --out are required"; exit 2; }
mkdir -p "$OUT" "$HISTORY"
OUT=$(cd "$OUT" && pwd)
: >"$OUT/metrics.jsonl"
echo broken >"$OUT/verdict"

# The DNS lab's programs: the Ubuntu 24.04 packages of docs/dns-stress.md,
# from the signed archive (`apt-get download` checks them against the
# release files apt trusts), unpacked without root. Kept between nights.
PKGS="dnsperf knot knot-dnsutils unbound jq libbpf1 libcap-ng0 libck0t64 libdnssec9t64 libedit2
libevent-2.1-7t64 libfstrm0 libhiredis1.1.0 libjq1 libknot14t64 libldns3t64 liblmdb0 libmnl0
libnghttp2-14 libonig5 libprotobuf-c1 liburcu8t64 libxdp1 libzscanner4t64"
if [ -z "$TOOLS" ]; then
	TOOLS=$CARGO_TARGET_DIR/nightly-tools
	if [ ! -x "$TOOLS/root/usr/bin/dnsperf" ]; then
		mkdir -p "$TOOLS/debs" "$TOOLS/root"
		# shellcheck disable=SC2086
		(cd "$TOOLS/debs" && apt-get download $PKGS)
		for d in "$TOOLS"/debs/*.deb; do dpkg-deb -x "$d" "$TOOLS/root"; done
	fi
	TOOLS=$TOOLS/root
fi

(cd "$ROOT" && cargo build -q --release -p corerouter-daemon -p corerouter-cli)

# The labs. A lab that fails (a check, a crash) makes the night broken:
# its numbers would compare a broken run.
lab_ok=1
if ! "$ROOT/scripts/dns-stress-lab.sh" --userns --tools "$TOOLS" --daemon build \
	--tests "$TESTS" --duration "$DUR" --out "$OUT/dns" >"$OUT/dns.log" 2>&1; then
	lab_ok=0
fi
[ -f "$OUT/dns/metrics.jsonl" ] && cat "$OUT/dns/metrics.jsonl" >>"$OUT/metrics.jsonl"

# What came in since the last green night (its file is <date>-<sha>.green.jsonl).
last=$(find "$HISTORY" -maxdepth 1 -name '*.green.jsonl' -printf '%f\n' | sort | tail -n 1)
: >"$OUT/commits.txt"
if [ -n "$last" ]; then
	sha=${last%.green.jsonl}
	sha=${sha#*-}
	git -C "$ROOT" log --format='%h %s' "$sha..HEAD" >"$OUT/commits.txt" 2>/dev/null ||
		echo "(commit $sha of the last green night is not in this clone)" >"$OUT/commits.txt"
fi

if [ "$lab_ok" = 1 ] && [ -s "$OUT/metrics.jsonl" ]; then
	(cd "$ROOT" && cargo xtask nightly compare --metrics "$OUT/metrics.jsonl" --history "$HISTORY" \
		--report "$OUT/report.md" --commits "$OUT/commits.txt") >"$OUT/compare.log" 2>&1 || true
	v=$(tail -n 1 "$OUT/compare.log")
	case $v in
	"verdict: ok") echo ok >"$OUT/verdict" ;;
	"verdict: regressed") echo regressed >"$OUT/verdict" ;;
	*) { echo "the comparison failed:"; tail -n 20 "$OUT/compare.log"; } >"$OUT/report.md" ;;
	esac
else
	{
		echo "Um laboratório falhou: a noite não é comparada."
		echo
		echo '```'
		grep -E 'FAIL|falh|panic|died' "$OUT/dns.log" | head -n 20 || tail -n 20 "$OUT/dns.log"
		echo '```'
	} >"$OUT/report.md"
fi
echo "nightly-regress: $(cat "$OUT/verdict") ($(wc -l <"$OUT/metrics.jsonl") metrics)"
