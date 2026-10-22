#!/usr/bin/env bash
# Fila de entrada: integra PRs prontos na `main` (AGENTS.md, "Integração").
#
# Uso: scripts/land.sh [--watch | --batch] [--fold] [<pr>...]
#
# --watch: fila contínua — pega sozinha os PRs com o rótulo `fila` e roda os lotes abaixo, com um
#   lote especulativo montado em cima do que está no CI (veja `watch`).
#
# --batch (o normal): um CI para a combinação, não um por PR.
#   1. junta numa branch temporária (`queue/batch-<hora>`) a `main` e os PRs, em ordem; um PR que
#      conflita de verdade fica de fora (a sessão dona resolve); conflito só nos documentos do
#      fold é resolvido sozinho;
#   2. faz o fold nessa combinação (confere os docs/changes) e roda o CI completo
#      (`workflow_dispatch`): é o que a `main` vai ser, então "sozinho passa, junto quebra"
#      aparece aqui;
#   3. verde: squash de cada PR em ordem (os checks rápidos do próprio PR precisam estar verdes);
#   4. vermelho: bisseção — divide ao meio e repete em cada metade, a da direita sobre a `main`
#      que já recebeu a da esquerda, até isolar quem quebra (~log2 N CIs); quem quebra fica de fora.
#   Medido: lote de 1 a 4 PRs em 220–348 s, contra ~2,5–4 min por PR no um por um.
#
# Fold (consolidar docs/changes em log, gaps, histórico e perf): periódico, como no
# towncrier/changesets, que só consolidam no release. Só com --fold (sozinho ou junto) ou quando
# houver FOLD_MIN (10) arquivos pendentes; até lá, `cargo xtask docs pending` mostra os status de
# gap ainda não consolidados.
#
# Sem --batch, um por um: merge da `main` na branch do PR, fold, push, CI completo disparado no
# commit que vai entrar, squash; para no primeiro problema.
#
# Ambiente: BASE (padrão main); LAND_DIR (padrão <repo>/target-land: worktrees e o target do
# xtask, fora do git); FOLD_MIN (padrão 10).
set -euo pipefail

batch=0 fold=0 watch=0
while [ $# -gt 0 ]; do
  case "$1" in
    --batch) batch=1 ;;
    --watch) watch=1 ;;
    --fold) fold=1 ;;
    *) break ;;
  esac
  shift
done
[ $# -ge 1 ] || [ "$fold" = 1 ] || [ "$watch" = 1 ] ||
  { echo "uso: scripts/land.sh [--watch | --batch] [--fold] [<pr>...]" >&2; exit 2; }

root=$(git rev-parse --show-toplevel)
base=${BASE:-main}
dir=${LAND_DIR:-$root/target-land}
repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
export CARGO_TARGET_DIR="$dir/target"
mkdir -p "$dir"

say() { printf '%s\n' "$*"; }
stop() { say "PARADO em #$1: $2"; exit 1; }

# Os checks exigidos pela proteção da main (nomes).
required=$(gh api "repos/$repo/branches/$base/protection/required_status_checks" \
  --jq '.checks[].context' 2>/dev/null || true)
n_required=$(printf '%s\n' "$required" | grep -c . || true)

# Espera os checks exigidos aparecerem e terminarem no commit `sha`. 0: verdes; 1: algum falhou
# (nomes em $failed); 2: não terminou em 30 min.
failed=""
# O CI do commit `sha`, uma consulta: 0 verde; 1 vermelho; 3 ainda rodando (ou nenhum run ainda).
# Todo run do `ci` nesse commit conta (o portão rápido do PR e o completo que a fila dispara).
check_once() {
  local sha=$1 runs
  failed=""
  # Fonte: os runs do workflow `ci` desse commit (Actions), não os check-runs: o GitHub já deixou
  # um check-run "in_progress" para sempre num job que tinha terminado verde (2026-10-22, lote
  # do #94), e a fila ficou esperando. Todos os runs do commit têm de terminar; um vermelho
  # reprova.
  runs=$(gh api "repos/$repo/actions/runs?head_sha=$sha&per_page=30" \
    --jq '.workflow_runs[] | select(.name == "ci") | "\(.status) \(.conclusion)"') || return 3
  [ -n "$runs" ] || return 3
  if printf '%s\n' "$runs" | grep -qv '^completed '; then
    return 3
  fi
  if printf '%s\n' "$runs" | grep -qE ' (failure|timed_out|startup_failure|action_required)$'; then
    failed=" ci"
    return 1
  fi
  printf '%s\n' "$runs" | grep -q ' success$' || return 3
  return 0
}

wait_checks() {
  local sha=$1 r
  for _ in $(seq 1 180); do
    r=0
    check_once "$sha" || r=$?
    [ "$r" = 3 ] || return "$r"
    sleep 10
  done
  return 2
}

checks_or_stop() {
  local n=$1 sha=$2 r=0
  wait_checks "$sha" || r=$?
  case $r in
    0) ;;
    1) stop "$n" "CI vermelho em${failed} (gh run view --log-failed)" ;;
    *) stop "$n" "o CI não terminou em 30 min" ;;
  esac
}

# Documentos que só o fold escreve. Um conflito neles não é de verdade: vem de uma branch que
# guardou um fold de uma rodada anterior da fila (que parou no meio). Log, histórico e perf só
# recebem acréscimos: ficam as entradas dos dois lados. No gaps.md, uma linha de gap que mudou
# dos dois lados fica uma só (a do PR, a mais nova).
FOLD_DOCS="docs/log.md docs/gaps-history.md docs/perf.md docs/gaps.md"

# `git merge` de $1 (mensagem $2) que resolve sozinho os conflitos só em FOLD_DOCS. 0: limpo ou
# resolvido; 1: conflito de verdade (merge abortado; arquivos em $conflicts).
conflicts=""
merge_fold_aware() {
  local f
  conflicts=""
  git merge --quiet --no-edit "$1" -m "$2" >/dev/null 2>&1 && return 0
  conflicts=$(git diff --name-only --diff-filter=U | tr '\n' ' ')
  for f in $conflicts; do
    case " $FOLD_DOCS " in
      *" $f "*) ;;
      *) git merge --abort; return 1 ;;
    esac
  done
  for f in $conflicts; do
    git show ":1:$f" > "$f.base" 2>/dev/null || : > "$f.base"
    git show ":2:$f" > "$f.ours"
    git show ":3:$f" > "$f.theirs"
    git merge-file -p --union "$f.ours" "$f.base" "$f.theirs" > "$f"
    rm -f "$f.base" "$f.ours" "$f.theirs"
    if [ "$f" = docs/gaps.md ]; then
      # A mesma gap duas vezes: fica a última (o lado do PR vem depois no union).
      awk -F' [|] ' '/^\| G[0-9]/ { id = $1; last[id] = NR } { line[NR] = $0; ids[NR] = (/^\| G[0-9]/ ? $1 : "") }
        END { for (i = 1; i <= NR; i++) if (ids[i] == "" || last[ids[i]] == i) print line[i] }' "$f" > "$f.tmp"
      mv "$f.tmp" "$f"
    fi
    git add "$f"
  done
  git commit --quiet --no-edit
  say "  conflito só nos documentos do fold ($conflicts): resolvido, entradas dos dois lados"
  return 0
}

# Um PR que o GitHub marca em conflito com a main não entraria no squash, mesmo que o lote o
# resolva: se o conflito é só nos documentos do fold, a main entra na própria branch (push) antes.
# Devolve o head novo em $head; 1 se o conflito é de verdade.
refresh_if_conflicting() {
  local n=$1 branch=$2 m="" w
  for _ in 1 2 3 4 5 6; do
    m=$(gh pr view "$n" --json mergeable --jq .mergeable)
    [ "$m" != UNKNOWN ] && break
    sleep 5
  done
  [ "$m" = CONFLICTING ] || return 0
  w="$dir/refresh-$n"
  git -C "$root" worktree remove --force "$w" 2>/dev/null || true
  git -C "$root" worktree add --quiet --detach "$w" "origin/$branch"
  if (cd "$w" && merge_fold_aware "origin/$base" "Merge origin/$base em $branch (fila de entrada)" &&
    git push --quiet origin "HEAD:refs/heads/$branch"); then
    head=$(git -C "$w" rev-parse HEAD)
    git -C "$root" worktree remove --force "$w"
    return 0
  fi
  git -C "$root" worktree remove --force "$w"
  return 1
}

# Squash com o título do PR: sem isso o GitHub usa a mensagem do primeiro commit quando a branch
# tem um só autor de commits ("wip hotspots (#79)" foi parar na main).
squash() {
  local n=$1 sha=$2 title
  title=$(gh pr view "$n" --json title --jq .title)
  gh pr merge -R "$repo" "$n" --squash --subject "$title (#$n)" --match-head-commit "$sha"
}

pr_info() {
  gh pr view "$1" --json state,isCrossRepository,headRefName,headRefOid \
    --jq '"\(.state) \(.isCrossRepository) \(.headRefName) \(.headRefOid)"'
}

# Head de cada PR do lote (pode mudar: refresh_if_conflicting).
declare -A HEADS=()
members=()

# Monta a combinação `main` + PRs (os que entram limpos ficam em $members), faz o fold nela e roda o
# CI completo uma vez. 0: verde; 1: vermelho; 2: ninguém entrou na combinação.
# Monta numa worktree ($2) a combinação de `$1` (a main, ou a branch de um lote em andamento) com
# os PRs, faz o fold, envia a branch `queue/batch-<hora>` e dispara o CI completo nela. Deixa em
# $members os que entraram limpos, em $combo_sha/$combo_branch o resultado. 0: disparado; 2:
# ninguém entrou; 1: docs/changes inválido. Quem fica de fora vai para SKIP (até a branch mudar).
declare -A SKIP=()
combo_sha="" combo_branch=""
build_combo() {
  local from=$1 name=$2 n state cross branch head wt
  shift 2
  members=()
  git -C "$root" fetch --quiet origin "$base"
  case "$from" in origin/queue/*) git -C "$root" fetch --quiet origin "${from#origin/}" ;; esac
  wt="$dir/$name"
  git -C "$root" worktree remove --force "$wt" 2>/dev/null || true
  git -C "$root" worktree add --quiet --detach "$wt" "$from"
  cd "$wt"
  for n in "$@"; do
    read -r state cross branch head < <(pr_info "$n")
    if [ "$state" != OPEN ]; then
      say "  #$n fora: o PR está $state"
      continue
    fi
    if ! refresh_if_conflicting "$n" "$branch"; then
      say "  #$n fora: conflito com a $base — a sessão dona resolve"
      SKIP[$n]=$head
      continue
    fi
    git fetch --quiet origin "$branch"
    if [ "$(git rev-parse "origin/$branch")" != "$head" ]; then
      say "  #$n fora: a branch andou durante a fila"
      continue
    fi
    if merge_fold_aware "origin/$branch" "lote: #$n"; then
      members+=("$n")
      HEADS[$n]=$head
    else
      say "  #$n fora: conflito com o lote em $conflicts— a sessão dona resolve"
      SKIP[$n]=$head
    fi
  done
  if [ ${#members[@]} = 0 ]; then
    cd "$root"
    return 2
  fi
  if ! cargo xtask docs fold >/dev/null; then
    cd "$root"
    say "  docs/changes inválido na combinação (cargo xtask docs)"
    return 1
  fi
  git add -A docs
  git commit --quiet -m "lote: consolida docs/changes" || true
  combo_sha=$(git rev-parse HEAD)
  combo_branch="queue/batch-$(date +%s%N | cut -c1-13)"
  git push --quiet origin "HEAD:refs/heads/$combo_branch"
  gh workflow run ci.yml --ref "$combo_branch" >/dev/null
  say "== lote ${members[*]}: CI da combinação ($(git rev-parse --short HEAD), sobre ${from#origin/})"
  cd "$root"
  return 0
}

drop_branch() {
  [ -n "$1" ] && git push --quiet origin --delete "$1" 2>/dev/null || true
}

# Monta a combinação `main` + PRs e espera o CI. 0: verde; 1: vermelho; 2: ninguém entrou.
test_combo() {
  local r=0
  build_combo "origin/$base" batch "$@" || return $?
  wait_checks "$combo_sha" || r=$?
  drop_branch "$combo_branch"
  return $r
}

# Depois de PRs entrarem: o checkout principal (o de onde a fila roda) vai para a main nova e os
# binários são recompilados, para quem testa nunca rodar um build velho. Só se o checkout estiver
# na main e sem alterações (senão avisa e não mexe); LAND_REBUILD=0 desliga. O daemon que estiver
# rodando não é reiniciado (pode estar no meio de um teste): a GUI avisa quando o commit dele
# difere do dela.
refresh_checkout() {
  local head
  [ "${LAND_REBUILD:-1}" = 1 ] || return 0
  head=$(git -C "$root" symbolic-ref --quiet --short HEAD || true)
  if [ "$head" != "$base" ]; then
    say "  checkout em '${head:-detached}': não recompila"
    return 0
  fi
  if [ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]; then
    say "  checkout com alterações: não recompila"
    return 0
  fi
  if ! { git -C "$root" fetch --quiet origin "$base" && git -C "$root" merge --quiet --ff-only "origin/$base"; }; then
    say "  checkout não avançou para a $base (ff): não recompila"
    return 0
  fi
  if (cd "$root" && env -u CARGO_TARGET_DIR cargo build -q -p corerouter-daemon -p corerouter-gui -p corerouter-cli); then
    say "  checkout em $(git -C "$root" rev-parse --short HEAD), binários recompilados (reinicie o daemon para usar)"
  else
    say "  aviso: o build do checkout falhou"
  fi
}

# Squash de cada PR de $members (os checks rápidos do próprio PR têm de estar verdes).
merge_members() {
  local n r merged=0
  for n in "${members[@]}"; do
    r=0
    wait_checks "${HEADS[$n]}" || r=$?
    if [ $r != 0 ]; then
      say "  #$n fora: o CI do próprio PR está vermelho (${failed:-tempo})"
      continue
    fi
    if squash "$n" "${HEADS[$n]}"; then
      say "  #$n entrou"
      merged=1
    else
      say "  #$n fora: o merge foi recusado (a branch mudou?)"
    fi
  done
  [ "$merged" = 0 ] || refresh_checkout
}

# Integra os PRs: testa a combinação; verde, entram todos; vermelho, divide ao meio e repete em
# cada metade (bisseção: ~log2 N CIs para achar o culpado, em vez de N no um por um). A metade da
# direita é testada sobre a main que já recebeu a da esquerda.
land_set() {
  local r=0 half
  [ $# -gt 0 ] || return 0
  test_combo "$@" || r=$?
  case $r in
    0) merge_members; return 0 ;;
    2) return 0 ;;
  esac
  local set=("${members[@]}")
  if [ ${#set[@]} = 1 ]; then
    say "  #${set[0]} fora: quebra o CI (${failed:-tempo}) — a sessão dona corrige na branch"
    return 0
  fi
  say "  vermelho (${failed:-tempo}): dividindo ${set[*]}"
  half=$(( ${#set[@]} / 2 ))
  land_set "${set[@]:0:$half}"
  land_set "${set[@]:$half}"
}

# Fold dos docs/changes pendentes num PR próprio (a main é protegida). Periódico, como no
# towncrier/changesets (que só consolidam no release): só com --fold ou com FOLD_MIN arquivos
# pendentes; até lá `cargo xtask docs pending` mostra os status ainda não consolidados.
FOLD_MIN=${FOLD_MIN:-10}
maybe_fold() {
  local wt pending fb fpr
  git -C "$root" fetch --quiet origin "$base"
  pending=$(git -C "$root" ls-tree --name-only "origin/$base" docs/changes/ | grep -vc 'README.md$' || true)
  if [ "$fold" != 1 ] && [ "$pending" -lt "$FOLD_MIN" ]; then
    [ "$pending" -gt 0 ] && say "fold adiado: $pending arquivo(s) em docs/changes (consolida com $FOLD_MIN ou --fold)"
    return 0
  fi
  [ "$pending" -gt 0 ] || return 0
  wt="$dir/fold"
  git -C "$root" worktree remove --force "$wt" 2>/dev/null || true
  git -C "$root" worktree add --quiet --detach "$wt" "origin/$base"
  cd "$wt"
  cargo xtask docs fold >/dev/null || stop fold "fold falhou na main"
  fb="queue/fold-$(date +%s)"
  git add -A docs
  git commit --quiet -m "docs: consolida docs/changes ($pending arquivos)"
  git push --quiet origin "HEAD:refs/heads/$fb"
  fpr=$(gh pr create --base "$base" --head "$fb" \
    --title "docs: consolida docs/changes ($pending arquivos)" \
    --body "Fold da fila de entrada (scripts/land.sh)." | grep -o '[0-9]*$')
  checks_or_stop "$fpr" "$(git rev-parse HEAD)"
  gh pr merge -R "$repo" "$fpr" --squash --delete-branch --match-head-commit "$(git rev-parse HEAD)" ||
    stop "$fpr" "o merge do fold foi recusado"
  say "  fold #$fpr entrou ($pending arquivos)"
  cd "$root"
  git worktree remove --force "$wt"
}

# PRs prontos: abertos, para a main, não rascunho, com o rótulo `fila`, fora dos que ficaram de
# fora (SKIP) enquanto a branch deles não mudar.
ready_prs() {
  local n head
  gh pr list --base "$base" --state open --label fila --limit 100 \
    --json number,isDraft,headRefOid --jq '.[] | select(.isDraft | not) | "\(.number) \(.headRefOid)"' |
    while read -r n head; do
      [ "${SKIP[$n]:-}" = "$head" ] || printf '%s\n' "$n"
    done
}

# --watch: fila contínua. A cada WATCH_TICK segundos pega os PRs prontos (rótulo `fila`):
# - sem lote em andamento: monta um com todos e dispara o CI da combinação;
# - com lote em andamento: os PRs novos entram num lote especulativo montado **em cima dele**, com
#   o próprio CI, rodando ao mesmo tempo;
# - lote verde: squash dos PRs; o especulativo (se houver) vira o lote em andamento, já com o CI
#   adiantado — testou exatamente main + lote + PRs novos;
# - lote vermelho: o especulativo é descartado e o lote passa pela bisseção (land_set).
# Para depois de WATCH_IDLE segundos sem nada para fazer.
watch() {
  local tick=${WATCH_TICK:-20} max_idle=${WATCH_IDLE:-1800} idle=0 r n
  local run=() run_sha="" run_branch="" spec=() spec_sha="" spec_branch="" ready=() new=()
  gh label create fila --color 0E8A16 --description "Pronto para a fila de entrada" 2>/dev/null || true
  say "fila contínua: rótulo 'fila', a cada ${tick}s"
  while :; do
    mapfile -t ready < <(ready_prs)
    if [ -z "$run_sha" ] && [ ${#ready[@]} -gt 0 ]; then
      if build_combo "origin/$base" batch "${ready[@]}"; then
        run=("${members[@]}") run_sha=$combo_sha run_branch=$combo_branch
      fi
    elif [ -n "$run_sha" ] && [ -z "$spec_sha" ]; then
      new=()
      for n in "${ready[@]}"; do
        case " ${run[*]} " in *" $n "*) ;; *) new+=("$n") ;; esac
      done
      if [ ${#new[@]} -gt 0 ] && build_combo "origin/$run_branch" spec "${new[@]}"; then
        spec=("${members[@]}") spec_sha=$combo_sha spec_branch=$combo_branch
        say "   (especulativo, sobre o lote ${run[*]})"
      fi
    fi
    if [ -n "$run_sha" ]; then
      r=0
      check_once "$run_sha" || r=$?
      case $r in
        0)
          members=("${run[@]}")
          merge_members
          drop_branch "$run_branch"
          run=() run_sha="" run_branch=""
          if [ -n "$spec_sha" ]; then
            run=("${spec[@]}") run_sha=$spec_sha run_branch=$spec_branch
            spec=() spec_sha="" spec_branch=""
            say "   o especulativo ${run[*]} vira o lote em andamento"
          fi
          ;;
        1)
          say "  lote ${run[*]} vermelho (${failed}): especulativo descartado, bisseção"
          drop_branch "$run_branch"
          drop_branch "$spec_branch"
          local again=("${run[@]}")
          run=() run_sha="" run_branch="" spec=() spec_sha="" spec_branch=""
          land_set "${again[@]}"
          ;;
      esac
    fi
    if [ -z "$run_sha" ] && [ ${#ready[@]} = 0 ]; then
      idle=$((idle + tick))
      if [ "$idle" -ge "$max_idle" ]; then
        say "fila contínua: ${max_idle}s sem PR pronto, encerrando"
        break
      fi
    else
      idle=0
    fi
    sleep "$tick"
  done
}

serial=("$@")
if [ "$watch" = 1 ]; then
  watch
  serial=()
elif [ "$batch" = 1 ]; then
  land_set "$@"
  serial=()
fi

for n in "${serial[@]}"; do
  read -r state cross branch < <(gh pr view "$n" \
    --json state,isCrossRepository,headRefName --jq '"\(.state) \(.isCrossRepository) \(.headRefName)"')
  [ "$state" = OPEN ] || stop "$n" "o PR está $state"
  [ "$cross" = false ] || stop "$n" "PR de fork: integre à mão"
  say "== #$n ($branch)"

  git -C "$root" fetch --quiet origin "$base" "$branch"
  wt="$dir/pr-$n"
  git -C "$root" worktree remove --force "$wt" 2>/dev/null || true
  git -C "$root" worktree add --quiet --detach "$wt" "origin/$branch"
  cd "$wt"

  if ! merge_fold_aware "origin/$base" "Merge origin/$base em $branch (fila de entrada)"; then
    stop "$n" "conflito real com a $base em: $conflicts— a sessão dona resolve na branch"
  fi

  cargo xtask docs fold >/dev/null || stop "$n" "docs/changes inválido (cargo xtask docs)"
  if [ -n "$(git status --porcelain)" ]; then
    git add -A docs
    git commit --quiet -m "docs: consolida docs/changes (#$n)"
  fi

  sha=$(git rev-parse HEAD)
  if [ "$sha" != "$(git rev-parse "origin/$branch")" ]; then
    say "  push $(git rev-parse --short HEAD)"
    git push --quiet origin "HEAD:refs/heads/$branch" || stop "$n" "push recusado (a branch andou?)"
  fi

  # O CI do PR é o portão rápido; o completo (testes contra o kernel) roda aqui, no commit que
  # vai entrar.
  gh workflow run ci.yml --ref "$branch" >/dev/null
  # Espera o run disparado aparecer, senão o portão rápido (já verde) passaria por ele.
  for _ in $(seq 1 30); do
    gh run list --workflow ci.yml --branch "$branch" --event workflow_dispatch --commit "$sha" \
      --json databaseId --jq 'length' | grep -qv '^0$' && break
    sleep 4
  done
  if [ "$n_required" -gt 0 ]; then
    say "  esperando os $n_required checks exigidos (rápido do PR + completo)"
    checks_or_stop "$n" "$sha"
  fi

  squash "$n" "$sha" || stop "$n" "o merge foi recusado"
  say "  #$n entrou"
  refresh_checkout

  cd "$root"
  git worktree remove --force "$wt"
done

maybe_fold
git -C "$root" fetch --quiet origin "$base"
say "fila concluída: $*"
