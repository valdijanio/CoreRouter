# ospfd: max-lsa (G3.4r)

Envio ao FRR, para o usuário publicar (`docs/upstream.md`). É um PR no `ospfd` com dois commits,
aplicáveis no `master` de 2026-11-12 (`622c8322d2`): a mudança e o topotest. Os patches estão nesta
pasta, com autor provisório `CoreRouter <noreply@corerouter>` e **sem** `Signed-off-by`, porque a
assinatura é do usuário.

A versão da imagem (10.7.1 sobre os patches 0001–0006) está em
`os/patches/frr/0007-ospfd-max-lsa.patch`: o mesmo código, com o contexto da 10.7.1. A análise, em
português, está em `docs/ospf.md` ("Proteção da LSDB"); o texto abaixo, em inglês, vai para o
GitHub.

Conferido antes do envio:

- `checkpatch` 0/0;
- `git clang-format` (18) e `black` sem diferenças;
- compila sem avisos na 10.7.1 e no `master`;
- topotests na VM do laboratório (`scripts/frr-topotests.sh`, base `622c8322d2` sem e com o
  patch, 13/11/2026):
  - `ospf_shutdown` e `ospf_topo1` passam nos dois builds;
  - o `ospf_max_lsa` novo falha sem o patch (o comando não existe);
  - com o patch, passaram convergência, ignore e isolated; o passo do `clear` esperava `Full/-`
    num enlace broadcast (falha do teste, não do `ospfd`) e agora usa `expect_ospfv2_neighbor`;
  - **falta repetir a rodada inteira com o teste corrigido antes do envio** (a VM estava
    reservada);
- bateria no laboratório do host com 190 000 LSAs.

## Comandos (o usuário roda)

```sh
cd /srv/build/frr && git fetch origin
P=/home/oem/code/CoreRouter/docs/frr-upstream/ospfd-max-lsa   # depois do merge do PR no CoreRouter
git switch -c ospfd-max-lsa origin/master && git am $P/0001-*.patch $P/0002-*.patch
git -c user.name="Nome Real" -c user.email="nome@exemplo.org" rebase origin/master \
  --exec 'git commit --amend --no-edit --reset-author -s'
git push fork ospfd-max-lsa
gh pr create --repo FRRouting/frr --base master --head <conta>:ospfd-max-lsa \
  --title "ospfd: max-lsa, a limit on the LSAs of other routers" --body-file PR.md
```

Depois de aberto, um comentário no [#23897](https://github.com/FRRouting/frr/pull/23897), que
trata do mesmo problema de outro jeito (texto abaixo, "Comment on #23897").

---

## PR text

### ospfd: max-lsa, a limit on the LSAs of other routers

ospfd installs every LSA it is flooded, without a limit. A wrong redistribution elsewhere in the
domain (a full BGP table into OSPF) runs every router of the area out of memory: each LSA costs
about 1.5 KiB in ospfd, and each route about 0.6 KiB in zebra.

Measured with FRR 10.7.1: one neighbor redistributes 192 721 kernel routes into a router with
no limit. 175 436 type-5 LSAs reach its database in the first second, all of them in 5.2 s.
ospfd grows to 293 MiB and zebra to 120 MiB. The memory is not given back after the LSAs are
discarded (glibc keeps it). A check from outside that polls `show ip ospf json` comes after the
whole flood, so the limit has to be in ospfd.

This adds, under `router ospf`:

```
max-lsa (1-4294967294) [threshold (1-100)] [warning-only] [ignore-time (30-3600)]
        [ignore-count (1-32)] [reset-time (60-86400)]
clear ip ospf [(1-65535)|vrf NAME] max-lsa
```

It uses the semantics of Cisco `max-lsa` and Junos `database-protection`:

- only the LSAs of other routers count, so a router's own redistribution never takes it down;
- a warning is logged at `threshold` percent (default 75);
- above the limit the instance goes down for `ignore-time` (default 300 s): its interfaces go
  down, so every adjacency drops, and the learned LSAs are discarded;
- then it comes back; after `ignore-count` such periods (default 5) it stays down until
  `clear ip ospf max-lsa`;
- `reset-time` (default 600 s) up resets the count of periods;
- `warning-only` only logs.

Why down as a whole, rather than refusing the LSAs over the limit: the databases of an area must
be the same in every router (RFC 2328, section 13). A router that keeps its adjacencies with a
partial database computes paths its neighbors do not. Without adjacencies, no router routes
through it. Its neighbors also stop retransmitting the refused LSAs to it forever.

Implementation:

- the check is an event scheduled from `ospf_lsa_install()` when an LSA of another router is
  added, so it runs once per pass of the event loop, after the packet that brought the LSA;
- it counts in O(areas), from the existing `count_self`;
- the down state is its own (`ospf->max_lsa.state`), not the `shutdown` configuration flag, so the
  running configuration does not change;
- `ospf_if_up()` and the external route handling check `ospf_is_down()`, which covers both;
- `show ip ospf` always shows the count of LSAs of other routers, and, when a limit is set, the
  limit, the state, the ignore periods and the time left (JSON: `lsaOtherRoutersCounter`,
  `maxLsa`).

Measured with the same flood and `max-lsa 50000 ignore-time 30 ignore-count 2`:

| | no limit | max-lsa 50000 |
|---|---|---|
| LSAs in the database at the peak | 192 721 | 50 008 |
| time until down | – | 817 ms |
| ospfd / zebra peak RSS | 293 / 120 MiB | 84 / 42 MiB |
| after two ignore periods and isolated | – | ospfd 124 MiB |
| `clear ip ospf max-lsa` to Full | – | 0.7–1.5 s |
| limit set below the count to down | – | 0.4 s |

The topotest `ospf_max_lsa` has a neighbor redistribute 120 statics against `max-lsa 100`. It
checks ignore (the adjacency and the learned LSAs gone, no `shutdown` in the configuration), the
return after `ignore-time`, isolated after `ignore-count`, `clear ip ospf max-lsa`,
`warning-only`, `threshold` and `no max-lsa`.

This is OSPFv2 only. ospf6d would need the same, in another PR.

## Comment on #23897

> Thanks for looking at this. We hit the same problem (a wrong redistribution flooding ~190 000
> type-5 LSAs; 293 MiB in ospfd) and sent #NNNN, which takes a different approach: above the limit the
> instance drops its adjacencies and learned LSAs for an ignore time, as Cisco `max-lsa` and Junos
> `database-protection` do, instead of refusing the LSAs over the limit. Refusing them leaves this
> router with a database different from its neighbors' while it keeps the adjacencies (RFC 2328
> section 13), and the neighbors retransmit the refused LSAs forever. A default limit of 100 000
> would also take down networks that run larger databases today (Cisco's 50 000 default in IOS XE
> 17.11 did, FN74009). Happy to merge the two if the maintainers prefer one PR.
