#!/usr/bin/env bash
# Fila de entrada: integra PRs prontos na `main`, um por vez (AGENTS.md, "Integração").
#
# Uso: scripts/land.sh <pr> [<pr>...]
#   A sessão principal roda depois que o usuário aprova o lote ("N features prontas — subir?").
#
# Por PR, em ordem:
#   1. worktree temporária na branch do PR e merge da `origin/main` (conflito real: para e diz
#      quais arquivos; a sessão dona resolve);
#   2. `cargo xtask docs fold`: consolida `docs/changes/*.md` em log, gaps e histórico (commit);
#   3. push (como você, então o `ci` do PR roda normalmente) e espera os checks exigidos do
#      commit novo. A proteção da `main` exige branch atualizada: o CI do PR roda sobre a `main`
#      em que ele vai entrar, e "sozinho passa, junto quebra" para aqui, não na `main`;
#   4. squash merge (`--match-head-commit`: nada entra que não tenha sido testado).
# Para no primeiro problema e diz qual PR e por quê; os PRs seguintes ficam para a próxima rodada.
#
# Ambiente: BASE (padrão main); LAND_DIR (padrão <repo>/target-land: worktrees e o target do
# xtask, fora do git).
set -euo pipefail

[ $# -ge 1 ] || { echo "uso: scripts/land.sh <pr> [<pr>...]" >&2; exit 2; }

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

# Espera os checks exigidos aparecerem e terminarem no commit `sha`; falha se algum não passar.
wait_checks() {
  local n=$1 sha=$2 runs pending failed
  for _ in $(seq 1 180); do
    runs=$(gh api "repos/$repo/commits/$sha/check-runs?per_page=100" \
      --jq '.check_runs[] | "\(.name)\t\(.status)\t\(.conclusion)"')
    pending=0 failed=""
    while IFS= read -r name; do
      [ -z "$name" ] && continue
      line=$(printf '%s\n' "$runs" | awk -F'\t' -v n="$name" '$1 == n' | head -n1)
      case "$line" in
        "") pending=1 ;;
        *$'\tcompleted\tsuccess') ;;
        *$'\tcompleted\t'*) failed="$failed $name" ;;
        *) pending=1 ;;
      esac
    done <<< "$required"
    [ -n "$failed" ] && stop "$n" "CI vermelho em${failed} (gh run view --log-failed)"
    [ "$pending" = 0 ] && return 0
    sleep 10
  done
  stop "$n" "o CI não terminou em 30 min"
}

for n in "$@"; do
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

  if ! git merge --quiet --no-edit "origin/$base" -m "Merge origin/$base em $branch (fila de entrada)"; then
    files=$(git diff --name-only --diff-filter=U | tr '\n' ' ')
    git merge --abort
    stop "$n" "conflito real com a $base em: $files— a sessão dona resolve na branch"
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

  if [ "$n_required" -gt 0 ]; then
    say "  esperando os $n_required checks exigidos"
    wait_checks "$n" "$sha"
  fi

  gh pr merge -R "$repo" "$n" --squash --match-head-commit "$sha" || stop "$n" "o merge foi recusado"
  say "  #$n entrou"

  cd "$root"
  git worktree remove --force "$wt"
done

git -C "$root" fetch --quiet origin "$base"
say "fila concluída: $*"
