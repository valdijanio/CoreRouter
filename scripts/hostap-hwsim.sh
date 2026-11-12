#!/usr/bin/env bash
# hostap's own hwsim tests (tests/hwsim) on a hostap tree, in the lab VM: the
# check of a wpa_supplicant/hostapd fix before it goes upstream
# (docs/upstream.md). mac80211_hwsim needs root, so the tests run in the VM.
#
#   scripts/hostap-hwsim.sh --host <hostap tree> [--diff <fix.diff>] [--repeat N] <test>...
#
# Test names go without the `test_` prefix (`scan_aborted_on_connect_no_reselect`);
# a trailing `*` matches a prefix (`'scan*'`).
#
# Host side: copies the tree (no .git, no build output) and the diff to
# /srv/hostap-up in the VM, runs this script there as root through
# `cargo xtask vm-lab run`, then `cargo xtask vm-lab reset`: the suite unloads
# cfg80211 and leaves the regulatory domain behind, and on 2026-11-12 that
# made wifi-bond-lab's access points refuse channels 36 and 149 (no-IR).
#
# VM side (--vm): installs the build and test dependencies, builds from
# clean (an incremental build kept the old binary after `patch -R`), runs the
# tests N times on the tree as it is. With --diff, also reverts the diff,
# rebuilds and runs them once more: a new test must fail there. The diff is
# re-applied at the end. Exit 1 if a test failed on the tree as it is.
set -uo pipefail

usage() {
	echo "usage: $0 --host <hostap tree> [--diff <fix.diff>] [--repeat N] <test>..." >&2
	exit 2
}

[ $# -ge 1 ] || usage
mode=$1
shift
case $mode in
--host)
	[ $# -ge 2 ] || usage
	tree=$(realpath "$1")
	shift
	diff=""
	pass=()
	while [ $# -gt 0 ]; do
		case $1 in
		--diff)
			diff=$(realpath "$2")
			shift 2
			;;
		*)
			pass+=("$1")
			shift
			;;
		esac
	done
	[ -d "$tree/tests/hwsim" ] || {
		echo "$tree is not a hostap tree (no tests/hwsim)" >&2
		exit 2
	}
	name=$(basename "$tree")
	tar c -C "$(dirname "$tree")" --exclude="$name/.git" --exclude="$name/build" \
		--exclude='*.o' --exclude='*.d' --exclude='*.orig' "$name" |
		cargo xtask vm-lab ssh 'sudo rm -rf /srv/hostap-up && sudo mkdir -p /srv/hostap-up && sudo tar x -C /srv/hostap-up' ||
		exit 1
	vmdiff=()
	if [ -n "$diff" ]; then
		cargo xtask vm-lab ssh 'sudo tee /srv/hostap-up/fix.diff >/dev/null' <"$diff" || exit 1
		vmdiff=(--diff /srv/hostap-up/fix.diff)
	fi
	cargo xtask vm-lab run -- bash scripts/hostap-hwsim.sh --vm "/srv/hostap-up/$name" "${vmdiff[@]}" "${pass[@]}"
	rc=$?
	cargo xtask vm-lab reset
	exit $rc
	;;
--vm) ;;
*) usage ;;
esac

[ $# -ge 2 ] || usage
H=$1
shift
diff=""
repeat=1
tests=()
while [ $# -gt 0 ]; do
	case $1 in
	--diff)
		diff=$2
		shift 2
		;;
	--repeat)
		repeat=$2
		shift 2
		;;
	*)
		tests+=("$1")
		shift
		;;
	esac
done
[ ${#tests[@]} -gt 0 ] || usage

export DEBIAN_FRONTEND=noninteractive
# What tests/hwsim/build.sh and the test modules need on Ubuntu: libnl,
# OpenSSL, D-Bus, pcap and curl/xml2 to build; bfd for CONFIG_WPA_TRACE_BFD
# of the example configs; iw and the Python modules the tests import.
apt-get -qq update >/dev/null &&
	apt-get -qq install -y build-essential pkg-config libnl-3-dev libnl-genl-3-dev \
		libnl-route-3-dev libssl-dev libdbus-1-dev libpcap-dev libcurl4-openssl-dev \
		libxml2-dev libsqlite3-dev binutils-dev libiberty-dev zlib1g-dev iw \
		python3-pyrad python3-cryptography python3-pycryptodome python3-openssl \
		python3-netifaces python3-dbus python3-gi >/dev/null 2>&1 ||
	{
		echo "apt-get failed"
		exit 1
	}
# wpa_supplicant registers fi.w1.wpa_supplicant1 on the system bus at start.
install -m 644 "$H/wpa_supplicant/dbus/dbus-wpa_supplicant.conf" \
	/etc/dbus-1/system.d/wpa_supplicant-hwsim.conf && systemctl reload dbus
trap 'cd "$H/tests/hwsim" && ./stop.sh >/dev/null 2>&1' EXIT

build() {
	make -C "$H/wpa_supplicant" clean >/dev/null 2>&1
	make -C "$H/hostapd" clean >/dev/null 2>&1
	if ! (cd "$H/tests/hwsim" && ./build.sh -f >/srv/hostap-up/build.log 2>&1); then
		echo "build failed (/srv/hostap-up/build.log):"
		grep -m5 -E "error|Error" /srv/hostap-up/build.log
		exit 1
	fi
	echo "build: ok ($1)"
}

failed=0
run() {
	cd "$H/tests/hwsim" || exit 1
	if ! ./start.sh >/srv/hostap-up/start.log 2>&1; then
		echo "start.sh failed:"
		tail -3 /srv/hostap-up/start.log
		exit 1
	fi
	out=$(./run-tests.py "${tests[@]}" 2>&1)
	echo "$out" | grep -E "^(PASS|FAIL|SKIP) |^passed|^failed|^skipped|Exception:"
	echo "$out" | grep -q "^FAIL " && failed=1
	./stop.sh >/dev/null 2>&1
}

build "tree as it is"
for i in $(seq "$repeat"); do
	echo "== run $i of $repeat, tree as it is"
	run
done
ok=$failed

if [ -n "$diff" ]; then
	echo "== without the diff (a new test must fail here)"
	patch -R -p1 -s -d "$H" <"$diff" || {
		echo "the diff does not revert"
		exit 1
	}
	build "without the diff"
	failed=0
	run
	patch -p1 -s -d "$H" <"$diff" && echo "diff re-applied"
fi

[ "$ok" = 0 ] && echo "result: every test passed on the tree as it is" || echo "result: FAIL on the tree as it is"
exit "$ok"
