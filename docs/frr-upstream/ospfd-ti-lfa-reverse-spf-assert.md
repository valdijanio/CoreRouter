# ospfd: TI-LFA aborts in get_reverse_distance() when a router-LSA leaves the LSDB

Published by the user's account on 2026-10-29: issue
[FRRouting/frr#24091](https://github.com/FRRouting/frr/issues/24091) and PR
[FRRouting/frr#24092](https://github.com/FRRouting/frr/pull/24092) (branch
`valdijanio:ospfd-ti-lfa-missing-router-lsa`, the two patches next to this file with the
author and `Signed-off-by` filled in). Below is the draft they came from.

---

## Issue

**Title:** ospfd: TI-LFA aborts with `assertion (w_lsa && w_lsa->data) failed` in get_reverse_distance()

### Describe the bug

With `fast-reroute ti-lfa` enabled, ospfd aborts:

```
OSPF: ospfd/ospf_spf.c:1269: get_reverse_distance(): assertion (w_lsa && w_lsa->data) failed
OSPF: Received signal 6 at 1793310086 (si_addr 0x6f000975ae, PC 0x7f045ac9ec0c); aborting...
OSPF: /opt/frr-dbg/lib/libfrr.so.0(zlog_backtrace_sigsafe+0x8a) [0x7f045b0ec484]
OSPF: /opt/frr-dbg/lib/libfrr.so.0(zlog_signal+0x188) [0x7f045b0ec315]
...
OSPF: /lib/x86_64-linux-gnu/libc.so.6(abort+0xdf) [0x7f045ac288ff]
OSPF: /opt/frr-dbg/lib/libfrr.so.0(zlog_msg_prio+0) [0x7f045b1a0099]
OSPF: /opt/frr-dbg/lib/frr/ospfd(+0xc01f6) [0x5fc64840f1f6]
OSPF: /opt/frr-dbg/lib/frr/ospfd(+0xc07f5) [0x5fc64840f7f5]
OSPF: /opt/frr-dbg/lib/frr/ospfd(ospf_spf_calculate+0x19a) [0x5fc648410563]
OSPF: /opt/frr-dbg/lib/frr/ospfd(+0xc3f10) [0x5fc648412f10]
OSPF: /opt/frr-dbg/lib/frr/ospfd(+0xc4604) [0x5fc648413604]
OSPF: /opt/frr-dbg/lib/frr/ospfd(ospf_ti_lfa_generate_p_spaces+0x37d) [0x5fc6484139dc]
OSPF: /opt/frr-dbg/lib/frr/ospfd(ospf_ti_lfa_compute+0x28) [0x5fc6484142bf]
OSPF: /opt/frr-dbg/lib/frr/ospfd(ospf_spf_calculate_area+0x7f) [0x5fc64841082a]
OSPF: /opt/frr-dbg/lib/frr/ospfd(ospf_spf_calculate_areas+0xea) [0x5fc648410956]
...
```

The same backtrace with symbols (gdb, the unit test below, FRR 10.7.1 built with `-O0 -g3`):

```
#3  _zlog_assert_failed (xref=..., extra=0x0) at lib/zlog.c:801
#4  get_reverse_distance (v=0x59d257a8ce80, l=0x59d257a8ac18, w_lsa=0x0) at ospfd/ospf_spf.c:1269
#5  ospf_spf_next (v=0x59d257a8ce80, area=0x59d257a893f0, candidate=...) at ospfd/ospf_spf.c:1432
#6  ospf_spf_calculate (area=..., root_lsa=..., new_table=..., all_rtrs=0x0, new_rtrs=0x0,
        is_dry_run=true, is_root_node=false) at ospfd/ospf_spf.c:1770
#7  ospf_ti_lfa_generate_q_spaces (area=..., p_space=..., dest=..., recursive=true, pc_path=0x0)
        at ospfd/ospf_ti_lfa.c:686
#8  ospf_ti_lfa_generate_p_space (area=..., child=..., protected_resource=..., recursive=true,
        pc_path=0x0) at ospfd/ospf_ti_lfa.c:841
#9  ospf_ti_lfa_generate_p_spaces (area=..., protection_type=OSPF_TI_LFA_LINK_PROTECTION)
        at ospfd/ospf_ti_lfa.c:952
```

watchfrr restarts ospfd, and every adjacency of the router goes down.

### Versions

- FRR 10.7.1 (the deb.frrouting.org package `10.7.1-0~ubuntu24.04.1`, and the `frr-10.7.1` tag
  built from source) and `master` at `4ac34f1afa` (2026-10-29): same code, same abort.
- Ubuntu 24.04, kernel 6.8, libyang 3.13.6.

### Root cause

The Q spaces of TI-LFA are reverse SPF trees (`ospf_ti_lfa_generate_q_spaces()` sets
`area->spf_reversed`). In `ospf_spf_next()`, for a point-to-point link V->W:

```c
w_lsa = ospf_lsa_lookup(area->ospf, area, OSPF_ROUTER_LSA, l->link_id, l->link_id);
...
if (type == LSA_LINK_TYPE_POINTOPOINT && area->spf_reversed)
        link_distance = get_reverse_distance(v, l, w_lsa);   /* assert(w_lsa && w_lsa->data) */
...
if (w_lsa == NULL) {    /* RFC 2328 16.1 (2b): examine the next link */
        ...
        continue;
}
```

The reverse distance is read from W's router-LSA **before** the RFC 2328 16.1 (2b) check that
the LSA exists. When V's router-LSA still lists a point-to-point link to W but W's router-LSA is
not in the LSDB, the forward SPF just skips W, while the reverse SPF asserts. (The comment in
`get_reverse_distance()` already covers an *incomplete* LSA for W, falling back to the forward
metric; an *absent* one never gets there.)

W's router-LSA leaves the LSDB while others still name it when W flushes it: a router-id change
on W (the LSA of the old id is premature-aged and removed) or `no router ospf` on W. Its
neighbors keep the link to W in their own router-LSAs until the adjacency goes down (dead
interval), and every SPF in between runs the TI-LFA reverse SPFs. In the debug build, the line
logged right before every abort is the reverse-SPF step over that link:

```
reverse-spf: root 10.255.0.4 V 10.255.0.2 (distance 30) link to W 10.255.0.1 metric 10:
  W router-LSA ABSENT; router-LSAs in LSDB 4
```

(10.255.0.1 is the old router-id of R1.)

### How to reproduce

**Deterministic, with the unit test of the PR** (`tests/ospfd/test_ospf_spf`): `topo6` is the
triangle of `topo1` plus RT4, which RT3 advertises a point-to-point link to but whose router-LSA
is not in the LSDB.

```
$ printf 'test ospf topology topo6 root rt1 ti-lfa\n' | tests/ospfd/test_ospf_spf
test# test ospf topology topo6 root rt1 ti-lfa
Aborted (core dumped)
```

**Live**, four routers in network namespaces on one host, each its own zebra + ospfd (`-N`),
point-to-point links in a square R1–R2–R3–R4–R1 (R3–R4 cost 20, the others 10), loopbacks
10.255.0.N/32. Minimal ospfd configuration (segment routing is not needed, it only adds
labels to the backup paths):

```
interface t1-2
 ip ospf network point-to-point
 ip ospf hello-interval 1
 ip ospf dead-interval 4
 ip ospf cost 10
 ip ospf area 0.0.0.0
exit
interface lo
 ip ospf area 0.0.0.0
 ip ospf passive
exit
router ospf
 ospf router-id 10.255.0.1
 fast-reroute ti-lfa
exit
```

Once the four are Full, on R1:

```
router ospf
 ospf router-id 10.255.1.1
end
clear ip ospf process
```

R1 aborts in 15 of 40 runs of FRR 10.7.1 (each from a fresh setup); with no router-id change
(start + link flap only) in 0 of 50.

### Expected behavior

The reverse SPF skips a router whose LSA is not in the LSDB, as the forward SPF does
(RFC 2328 16.1 (2b)), and the backup paths are computed from the remaining topology.

---

## Pull request

**Title:** ospfd: don't assert on a missing router-LSA in the TI-LFA reverse SPF

**Body:**

With `fast-reroute ti-lfa`, ospfd aborts in `get_reverse_distance()` (`assertion (w_lsa &&
w_lsa->data) failed`) when a router-LSA names a point-to-point neighbor whose own router-LSA is
not in the LSDB, e.g. right after that neighbor changed its router-id or removed `router ospf`
(its LSA is flushed while its neighbors still list it until the dead interval). The reverse SPF
of the Q spaces reads the reverse distance before the RFC 2328 16.1 (2b) check that skips a
missing LSA; the forward SPF skips the neighbor instead.

- `ospfd: don't assert on a missing router-LSA in the TI-LFA reverse SPF`: read the reverse
  distance only when the LSA was found; the existing check right below then skips W.
- `tests: ospfd TI-LFA with a router-LSA missing from the LSDB`: `topo6` in `test_ospf_spf`,
  which aborts without the fix. With it, the backup paths are those of `topo1` (RT4 is only
  skipped), and the output of the other topologies does not change.

Live: 10.7.1 aborted in 15 of 40 runs without the fix, 0 of 40 with it (27 absent-LSA steps
skipped, no route missing).

Fixes #24091
