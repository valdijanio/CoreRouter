#!/usr/bin/env bash
# Bateria da fila de entrada: 10 features sintéticas em paralelo, medidas de ponta a ponta,
# numa base descartável (`bench/queue`) que nunca vai para a main.
#
#   scripts/bench-queue/run.sh setup    # base bench/queue (main + commit opcional BASE_PATCH) e proteção
#   scripts/bench-queue/run.sh gen      # 10 worktrees bench/fNN com as features (gen-feature.sh)
#   scripts/bench-queue/run.sh local    # `cargo xtask ci` nas 10 ao mesmo tempo (como 10 sessões)
#   scripts/bench-queue/run.sh prs      # push + 10 PRs de uma vez; espera o CI de todos
#   scripts/bench-queue/run.sh land [N...]  # fila de entrada (BASE=bench/queue), em ordem
#   scripts/bench-queue/run.sh clean    # fecha PRs, apaga branches, proteção e worktrees
#
# Tempos em target-bench/log.tsv (fase, item, início, fim, segundos, resultado).
set -euo pipefail

root=$(git rev-parse --show-toplevel)
dir=$root/target-bench
base=bench/queue
repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
log=$dir/log.tsv
mkdir -p "$dir"
export PATH=$HOME/.cargo/bin:$PATH

now() { date +%s; }
record() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$(($4 - $3))" "$5" >> "$log"; }
nn() { printf '%02d' "$1"; }

setup() {
  git -C "$root" fetch --quiet origin main
  git -C "$root" push --quiet origin "origin/main:refs/heads/$base"
  # Mesma proteção da main: 3 checks, branch atualizada.
  gh api --silent -X PUT "repos/$repo/branches/$base/protection" --input - <<'JSON'
{"required_status_checks":{"strict":true,"contexts":["xtask ci (linux)","build (macos-latest)","build (windows-latest)"]},
 "enforce_admins":false,"required_pull_request_reviews":null,"restrictions":null}
JSON
  echo "base $base = $(git -C "$root" rev-parse --short origin/main), protegida"
}

gen() {
  git -C "$root" fetch --quiet origin "$base"
  for n in $(seq 1 10); do
    wt=$dir/f$(nn "$n")
    git -C "$root" worktree remove --force "$wt" 2>/dev/null || true
    git -C "$root" worktree add --quiet -B "bench/f$(nn "$n")" "$wt" "origin/$base"
    (cd "$wt" && bash "$root/scripts/bench-queue/gen-feature.sh" "$n" && git add -A &&
      git -c user.name=bench -c user.email=bench@localhost commit --quiet -m "G9.$n: feature sintética $(nn "$n") da bateria")
  done
  echo "10 features geradas em $dir/fNN"
}

local_ci() {
  local t0 pids=() n
  t0=$(now)
  for n in $(seq 1 10); do
    (
      wt=$dir/f$(nn "$n")
      s=$(now)
      if (cd "$wt" && CARGO_TARGET_DIR=$dir/t$(nn "$n") CARGO_INCREMENTAL=0 \
        cargo xtask ci > "$dir/local-f$(nn "$n").log" 2>&1); then r=ok; else r=FAIL; fi
      record local "f$(nn "$n")" "$s" "$(now)" "$r"
    ) &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p" || true; done
  record local total "$t0" "$(now)" "$(du -sh "$dir"/t?? | awk '{print $1}' | tr '\n' ' ')"
  grep -P '^local\t' "$log" | tail -11
}

prs() {
  local t0 n
  for n in $(seq 1 10); do
    git -C "$dir/f$(nn "$n")" push --quiet -u origin "bench/f$(nn "$n")" 2>/dev/null
  done
  t0=$(now)
  for n in $(seq 1 10); do
    gh pr create --base "$base" --head "bench/f$(nn "$n")" --title "G9.$n: bateria f$(nn "$n")" \
      --body "Feature sintética da bateria da fila de entrada (scripts/bench-queue). Não vai para a main." >/dev/null
  done
  record prs opened "$t0" "$(now)" ok
  # Espera o CI de todos (é a medição; o script é o único que consulta).
  local pending=1
  while [ "$pending" = 1 ]; do
    pending=0
    for n in $(seq 1 10); do
      sha=$(git -C "$dir/f$(nn "$n")" rev-parse HEAD)
      st=$(gh api "repos/$repo/commits/$sha/check-runs" \
        --jq '[.check_runs[] | select(.name | test("xtask ci|build \\("))] | if length < 3 then "wait" elif all(.status == "completed") then (if all(.conclusion == "success") then "ok" else "FAIL" end) else "wait" end')
      [ "$st" = wait ] && pending=1
    done
    [ "$pending" = 1 ] && sleep 20
  done
  for n in $(seq 1 10); do
    sha=$(git -C "$dir/f$(nn "$n")" rev-parse HEAD)
    gh api "repos/$repo/commits/$sha/check-runs" \
      --jq ".check_runs[] | [\"f$(nn "$n")\", .name, .started_at, .completed_at, .conclusion] | @tsv" >> "$dir/checks.tsv"
  done
  record prs ci-all "$t0" "$(now)" ok
  grep -P '^prs\t' "$log"
}

land() {
  local list=() n s
  if [ $# -gt 0 ]; then list=("$@"); else for n in $(seq 1 10); do list+=("$n"); done; fi
  for n in "${list[@]}"; do
    pr=$(gh pr list --head "bench/f$(nn "$n")" --base "$base" --state open --json number --jq '.[0].number')
    [ -n "$pr" ] || { echo "f$(nn "$n"): sem PR aberto"; continue; }
    s=$(now)
    if BASE=$base bash "$root/scripts/land.sh" "$pr" > "$dir/land-f$(nn "$n").log" 2>&1; then
      record land "f$(nn "$n")" "$s" "$(now)" ok
    else
      record land "f$(nn "$n")" "$s" "$(now)" "PARADO: $(grep PARADO "$dir/land-f$(nn "$n").log" | tail -1)"
      grep -P '^land\t' "$log" | tail -3
      return 1
    fi
  done
  grep -P '^land\t' "$log"
}

clean() {
  for n in $(seq 1 10); do
    pr=$(gh pr list --head "bench/f$(nn "$n")" --state open --json number --jq '.[0].number')
    [ -n "$pr" ] && gh pr close "$pr" --delete-branch >/dev/null
    git -C "$root" push --quiet origin --delete "bench/f$(nn "$n")" 2>/dev/null || true
    git -C "$root" worktree remove --force "$dir/f$(nn "$n")" 2>/dev/null || true
    git -C "$root" branch -D "bench/f$(nn "$n")" 2>/dev/null || true
  done
  gh api --silent -X DELETE "repos/$repo/branches/$base/protection" 2>/dev/null || true
  git -C "$root" push --quiet origin --delete "$base" 2>/dev/null || true
  echo "limpo (os logs ficam em $dir)"
}

case "${1:-}" in
  setup) setup ;;
  gen) gen ;;
  local) local_ci ;;
  prs) prs ;;
  land) shift; land "$@" ;;
  clean) clean ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
