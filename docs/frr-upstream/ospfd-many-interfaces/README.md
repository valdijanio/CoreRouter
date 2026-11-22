# FRR with thousands of OSPF interfaces (G3.4q)

Envio ao FRR a publicar pelo usuário (`docs/upstream.md`): três PRs, um por mantenedor (`lib`,
`ospfd`, `zebra`), cada um aplicável sozinho no `master` de 2026-11-12 (`622c8322d2`). Os patches
estão nesta pasta, com autor provisório `CoreRouter <noreply@corerouter>` e **sem**
`Signed-off-by` (a assinatura é do usuário). A análise, em português, está em
`docs/frr-many-interfaces.md`; o texto abaixo, em inglês, vai para o GitHub.

| PR | commits (`git am` nesta ordem) |
|---|---|
| A — `lib` | `0001-lib-batch-entering-existing-interfaces-while-reading.patch` |
| B — `ospfd` | `0002-ospfd-index-the-router-LSA-links-by-position.patch`, `0003-ospfd-log-a-full-router-LSA-once-not-once-per-link.patch`, `0004-ospfd-one-router-LSA-per-configuration-batch-not-one.patch`, `0006-tests-ospfd-with-many-interfaces-configured-in-a-bat.patch` |
| C — `zebra` | `0005-zebra-don-t-walk-the-early-route-queue-for-a-type-it.patch` |

## Comandos (o usuário roda)

O clone `/srv/build/frr` já tem o `origin` (FRRouting/frr) e o `fork` (o fork da conta do
usuário). Um branch por PR, cada um saindo do `master`:

```sh
cd /srv/build/frr && git fetch origin
P=/home/oem/code/CoreRouter/docs/frr-upstream/ospfd-many-interfaces   # depois do merge do PR no CoreRouter
git switch -c lib-interface-batch origin/master && git am $P/0001-*.patch
git switch -c ospfd-many-interfaces origin/master && git am $P/0002-*.patch $P/0003-*.patch $P/0004-*.patch $P/0006-*.patch
git switch -c zebra-early-route-by-type origin/master && git am $P/0005-*.patch
```

Assinar cada commit com o nome e o e-mail de verdade (troque o exemplo; `docs/upstream.md`, seção 2):

```sh
for b in lib-interface-batch ospfd-many-interfaces zebra-early-route-by-type; do
  git switch $b
  git -c user.name="Nome Real" -c user.email="nome@exemplo.org" rebase origin/master \
    --exec 'git commit --amend --no-edit --reset-author -s'
  git log --format='%an <%ae>%n%(trailers:key=Signed-off-by)' origin/master..HEAD
done
```

Enviar e abrir os PRs (o texto de cada um está abaixo; `--body-file` com o trecho salvo num
arquivo):

```sh
git push fork lib-interface-batch ospfd-many-interfaces zebra-early-route-by-type
gh pr create --repo FRRouting/frr --base master --head <conta>:lib-interface-batch \
  --title "lib: batch entering existing interfaces while reading a configuration" --body-file A.md
gh pr create --repo FRRouting/frr --base master --head <conta>:ospfd-many-interfaces \
  --title "ospfd: scale to thousands of interfaces" --body-file B.md
gh pr create --repo FRRouting/frr --base master --head <conta>:zebra-early-route-by-type \
  --title "zebra: don't walk the early route queue for a type it does not hold" --body-file C.md
```

Primeira contribuição numa área nova: o CI do FRR só roda depois que um mantenedor aprova o
workflow. Para a 10.7 (a versão da imagem) é preciso pedir backport no PR depois do merge.

---

## Common: how this was measured

All three come from the same lab: one router with N 802.1Q VLANs (each a /30, point-to-point, no
neighbor), "interface X / ip ospf network point-to-point / ip ospf area 0" for each, typed as one
configuration batch (between `XFRR_start_configuration` and `XFRR_end_configuration`, as
`vtysh -f` and frr-reload.py send it), then the same with `no ip ospf …`, then the VLANs removed.
mgmtd, zebra and ospfd run in a user + network namespace; times are wall clock until ospfd and
zebra are idle, and their CPU (utime + stime). FRR built with `-O2 -g -fno-omit-frame-pointer`,
profiled with `perf record -g` and `--call-graph dwarf`. The machine is shared (8–64 load from
other jobs), so each number is the median of the rounds and the load is given.

The script (`frr-ospf-many-ifaces.sh`, attached) needs only an FRR install tree, `iproute2` and
`python3`; no root.

Measured 2026-11-12/13 on a shared machine (load 4–64 from other jobs, given). Wall clock until
ospfd and zebra are idle, with ospfd CPU seconds in parentheses (less affected by load). 1000 and
4000 on 10.7.1: median of 3 rounds; the rest, one round.

With `vtysh -f` on a quiet machine (load ~2, 10.7.1, 4000 interfaces, 2 rounds each): enabling
9.8–11.3 s (8.2) → 0.4 s (0.3); disabling 13.0 s (12.8) → 0.8 s (0.7); one SPF 40–48 → 1–2 ms;
router-LSA sequence after enabling 0x80000fa0 (one instance per interface) → 0x80000001; zebra
creating the VLANs 4.0 → 2.9 s.

The same configuration typed line by line on ospfd's vty (as a management daemon does, which is
where we found it), across versions and sizes:

| version | interfaces | enable: before → after | disable: before → after | one SPF before → after (median ms) |
|---|---|---|---|---|
| 10.7.1 | 1000 | 0.6 (0.5) → 0.3 (0.1) | 0.9 (0.8) → 0.1 (0.1) | 3 → 0 |
| 10.7.1 | 4000 | 17.8 (15.9) → 0.6 (0.4) | 35.7 (27.9) → 1.3 (1.1) | 48 → 3 |
| 10.7.1 | 10000 | 307 (298) → 1.1 (0.9) | 604 (553) → 5.1 (4.7) | 121 → 4 |
| master | 4000 | 74.8 (47.0) → 0.4 (0.3) | 53.3 (50.4) → 0.8 (0.7) | 56 → 6 |
| master | 10000 | 237 (229) → 1.1 (0.9) | 686 (566) → 4.4 (4.1) | 136 → 4 |

The "before" rounds at 10000 ran at load 33–56, the "after" ones at 4–5; an "after" round under
load 18–64 gave 2.3–16.5 s to enable and 10.5–34.9 s to disable 10000, still ~30x less.

With 10000 interfaces the router-LSA is full at 5334 links: 21,794,886 "Out of space in LSA stream"
lines and 2.53 GB of log before, one "router-LSA is full with 5334 links, 4666 more left out" line
and 2.5 MB of log after. Router-LSA sequence after enabling: 0x80002710 before, 0x80000003 after.

zebra CPU to create the VLANs (median of 3, base and fix alternated): 10.7.1 with 4000,
5.3 → 3.9 s; master with 10000, 28.2 → 21.4 s.

---

## A.md — lib: batch entering existing interfaces while reading a configuration

### Problem

Reading a configuration with thousands of `interface` stanzas is quadratic, even inside a
configuration batch.

`interface IFNAME` commits its change to the northbound at once, together with anything pending
(`nb_cli_apply_changes_clear_pending()`), because the commands typed after it may need the
interface object (the reason given in fd396924d6, "KISS always batch yang config"). And a classic
(non-YANG) command commits whatever is pending before it runs (`cmd_execute_command_real()`).
Each commit validates and diffs the whole candidate configuration (`nb_candidate_commit()` →
`lyd_validate_all()`, `nb_config_diff()`, `lyd_dup()`), so with N interfaces the batch does N
commits of O(N) each.

In ospfd, typing the stanzas of 4000 VLANs, the `interface` lines alone took 8.7 s of the 12.4 s
(10.7.1), and 12.0 s of the 16.4 s to type the stanzas that take OSPF off again. On master the
whole batch took 74.8 s.

### Fix

When the interface already exists, the object the following commands need is there; the commit
only adds its northbound entry (`lib_interface_create()` marks it configured). So, while a batch is
read and nothing else is pending, `interface` now lets that change wait for the end of the batch,
also across the classic commands that follow, which do not depend on it
(`nb_cli_apply_changes_classic_safe()`, a `pending_classic_safe` flag on the vty). Everything else
keeps the current behavior: if any other change is pending, it is committed before the next
classic command, and an `interface` command commits it all, as before; an interface that does not
exist yet is committed at once so that it is created; outside a batch nothing changes.

### Tests

- `tests/lib`, `tests/ospfd`, `tests/zebra` unit tests: 119 passed, 5 skipped (same as master).
- `tests/topotests/ospf_many_interfaces` (in the ospfd PR) loads 300 interface stanzas with
  `vtysh -f` and checks the result interface by interface.
- `show running-config` after the batch: all 4000 interfaces with their `ip ospf` lines.

---

## B.md — ospfd: scale to thousands of interfaces

Three changes and a topotest, each commit on its own.

**1. `ospfd: index the router-LSA links by position`.** `ospf_if_lookup_by_lsa_pos()` walks every
interface of the area to find the one of a router-LSA link. The SPF calls it for each stub link
of the root (`ospf_intra_add_stub()`) and for the next hop of each neighbor of the root
(`ospf_nexthop_calculation()`), so every SPF is quadratic in the number of interfaces — in normal
operation, on every LSA change. Now each area keeps the interface of each link of the router-LSA
last built, filled where `lsa_pos_beg/lsa_pos_end` are set; an interface leaves the index when it
goes down and when it is freed. The function keeps its signature (so #22331, which touches the same
callers, still applies).

**2. `ospfd: log a full router-LSA once, not once per link`.** A router-LSA holds at most ~5330
links. Past that, `link_info_set()` logs "Out of space in LSA stream" for every link left out,
again on every new instance: with 10000 interfaces in one area, ospfd logged **21.8 million lines
(2.5 GB) in about two minutes**. Now it counts them and logs once when the router-LSA of an area
becomes full (links in it, links left out) and once when everything fits again.

**3. `ospfd: one router-LSA per configuration batch, not one per interface`.** Each interface that
comes up or goes down originates a new router-LSA at once (`ism_change_state()` →
`ospf_router_lsa_update_area()`), and building, installing and flooding it walks all the
interfaces of the area. Enabling OSPF on 10000 interfaces originated 10000 instances (sequence
0x80002710) and took 22 s even with the lib fix. Now, between `ospf_config_start()` and
`ospf_config_end()` (the callbacks of `XFRR_start/end_configuration` ospfd already has), the new
router-LSA waits for the end of the batch, at most `OSPF_ROUTER_LSA_BATCH_DELAY` (1 s) if the
batch never ends. Outside a batch nothing changes. Neighbors would discard most of those instances
anyway (MinLSArrival, RFC 2328 section 13 step 5a), and section 12.4 allows one new instance per
MinLSInterval; Cisco's `timers throttle lsa all` does the same idea for all changes, this only
groups configuration batches.

**4. `tests: ospfd with many interfaces configured in a batch`.** r1 with 300 dummy interfaces
configured by the `vtysh -f` that loads frr.conf. It checks that each stub route of r1 is directly
attached to the interface that owns the prefix (the lookup by position), that the router-LSA has
all the links, that r2 learns every prefix, and the same after a batch takes OSPF off 100
interfaces (the positions of the remaining links change) and another puts it back, neither of
them originating one router-LSA instance per interface.

**Tests.** In a VM (Ubuntu 24.04, kernel 7.0), master `622c8322d2` with and without the three
PRs, built with all daemons: `ospf_many_interfaces ospf_topo1 ospf_p2mp ospf_unnumbered
ospf_gr_topo1 ospf_tilfa_topo1 ospf_shutdown ospf_dual_stack` — 43 passed, 8 skipped, the same
on both. The new test alone: with the series 3 passed, 1 skipped (the memory leak report); without
it, `test_ospf_many_interfaces_batch_off_on` fails with `router-LSA 0x80000006 -> 0x8000006a`
(one instance for each of the 100 interfaces). Unit tests (`tests/lib`, `tests/ospfd`,
`tests/zebra`): 119 passed, 5 skipped, the same as master.

---

## C.md — zebra: don't walk the early route queue for a type it does not hold

Each connected address added walks the whole early route subqueue
(`rib_meta_queue_early_route_cleanup()`, from `connected_remove_kernel_for_connected()`) looking
for a kernel route to the same prefix. When thousands of interfaces come up together the queue
holds the connected and local routes of all of them, so the walk is quadratic: creating 4000 VLANs
in one `ip -batch`, `prefix_same()` and the walk were ~37% of zebra's CPU; with 10000, zebra spent
37 s of CPU.

The meta queue now counts its early routes by route type (incremented where they are queued,
decremented where they are processed or freed), and the cleanup returns at once when no route of
the type it looks for is queued. When there is one, it walks as before.

Unit tests: `tests/zebra` passes (as part of the 119 above).

Seen while measuring, already better on master: the RIB walk for kernel routes on every
interface event (`rib_update_handle_vrf_all()`) cost zebra 107.8 s to remove 10000 VLANs on
10.7.1 and 8.5 s on master, which batches it since 2b16c71752.
