#!/usr/bin/env bash
# Fila de entrada: integra PRs prontos na `main`, um por vez (AGENTS.md, "Integração").
#
# Uso: scripts/land.sh [--batch] <pr> [<pr>...]
#   A sessão principal roda depois que o usuário aprova o lote ("N features prontas — subir?").
#
# --batch (o normal com vários PRs): um CI só para a combinação, não um por PR.
#   1. junta numa branch temporária (`queue/batch-<hora>`) a `main` e todos os PRs, em ordem; um PR que
#      conflita sai do lote (a sessão dona resolve) e o resto segue;
#   2. `cargo xtask docs fold` e um CI (`workflow_dispatch`) nessa combinação: é o que a `main`
#      vai ser, então "sozinho passa, junto quebra" aparece aqui;
#   3. verde: squash de cada PR em ordem, sem esperar mais CI (os checks do próprio PR já estão
#      verdes, e a `main` termina igual à combinação testada); depois um PR do fold, com CI;
#   4. vermelho: cai no modo um por um para esses PRs, que acha qual quebrou.
#   Medido na bateria: um CI ~2,5 min; um por um eram ~2,5 min por PR.
#
# Sem --batch, por PR, em ordem:
#   1. worktree temporária na branch do PR e merge da `origin/main` (conflito real: para e diz
#      quais arquivos; a sessão dona resolve);
#   2. `cargo xtask docs fold`: consolida `docs/changes/*.md` em log, gaps e histórico (commit);
#   3. push (como você, então o `ci` do PR roda normalmente) e espera os checks exigidos do
#      commit novo: o CI do PR roda sobre a `main` em que ele vai entrar, e "sozinho passa,
#      junto quebra" para aqui, não na `main`;
#   4. squash merge (`--match-head-commit`: nada entra que não tenha sido testado).
# Para no primeiro problema e diz qual PR e por quê; os PRs seguintes ficam para a próxima rodada.
#
# Ambiente: BASE (padrão main); LAND_DIR (padrão <repo>/target-land: worktrees e o target do
# xtask, fora do git).
set -euo pipefail

batch=0
if [ "${1:-}" = --batch ]; then
  batch=1
  shift
fi
[ $# -ge 1 ] || { echo "uso: scripts/land.sh [--batch] <pr> [<pr>...]" >&2; exit 2; }

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
wait_checks() {
  local sha=$1 runs pending
  for _ in $(seq 1 180); do
    runs=$(gh api "repos/$repo/commits/$sha/check-runs?per_page=100" \
      --jq '.check_runs[] | "\(.name)\t\(.status)\t\(.conclusion)"')
    pending=0 failed=""
    # Every run of each required check on this commit counts (the PR's fast gate and the full
    # one the queue dispatches have the same names).
    while IFS= read -r name; do
      [ -z "$name" ] && continue
      lines=$(printf '%s\n' "$runs" | awk -F'\t' -v n="$name" '$1 == n')
      if [ -z "$lines" ] || printf '%s\n' "$lines" | grep -qv $'\tcompleted\t'; then
        pending=1
      elif printf '%s\n' "$lines" | grep -qv $'\tcompleted\tsuccess$'; then
        failed="$failed $name"
      fi
    done <<< "$required"
    [ -n "$failed" ] && return 1
    [ "$pending" = 0 ] && return 0
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

# Um lote: devolve (em $rest) os PRs que ficaram para o modo um por um.
rest=()
land_batch() {
  local n state cross branch head wt sha r=0 included=() heads=()
  git -C "$root" fetch --quiet origin "$base"
  wt="$dir/batch"
  git -C "$root" worktree remove --force "$wt" 2>/dev/null || true
  git -C "$root" worktree add --quiet --detach "$wt" "origin/$base"
  cd "$wt"
  for n in "$@"; do
    read -r state cross branch head < <(pr_info "$n")
    if [ "$state" != OPEN ] || [ "$cross" != false ]; then
      say "  #$n fora do lote: $state, fork=$cross"
      continue
    fi
    if ! refresh_if_conflicting "$n" "$branch"; then
      say "  #$n fora do lote: conflito com a $base em $conflicts— a sessão dona resolve"
      continue
    fi
    git fetch --quiet origin "$branch"
    if [ "$(git rev-parse "origin/$branch")" != "$head" ]; then
      say "  #$n fora do lote: a branch andou durante a fila"
      continue
    fi
    if merge_fold_aware "origin/$branch" "lote: #$n"; then
      included+=("$n")
      heads+=("$head")
    else
      say "  #$n fora do lote: conflito com o lote em $conflicts— a sessão dona resolve"
    fi
  done
  [ ${#included[@]} -gt 0 ] || { cd "$root"; return 0; }
  say "== lote: ${included[*]}"
  cargo xtask docs fold >/dev/null || stop "${included[0]}" "docs/changes inválido no lote (cargo xtask docs)"
  git add -A docs
  git commit --quiet -m "lote: consolida docs/changes" || true
  sha=$(git rev-parse HEAD)
  local qb
  qb="queue/batch-$(date +%s)"
  git push --quiet origin "HEAD:refs/heads/$qb"
  gh workflow run ci.yml --ref "$qb" >/dev/null
  say "  CI do lote ($(git rev-parse --short HEAD)), esperando os $n_required checks"
  wait_checks "$sha" || r=$?
  cd "$root"
  git push --quiet origin --delete "$qb" 2>/dev/null || true
  if [ $r != 0 ]; then
    say "  lote vermelho (${failed:-tempo}): um por um, para achar quem quebrou"
    rest=("${included[@]}")
    return 0
  fi
  local i
  for i in "${!included[@]}"; do
    n=${included[$i]}
    checks_or_stop "$n" "${heads[$i]}"
    squash "$n" "${heads[$i]}" ||
      stop "$n" "o merge foi recusado"
    say "  #$n entrou"
  done
  # O fold do lote entra como um PR próprio (a main é protegida).
  git -C "$root" fetch --quiet origin "$base"
  git -C "$root" worktree remove --force "$wt" 2>/dev/null || true
  git -C "$root" worktree add --quiet --detach "$wt" "origin/$base"
  cd "$wt"
  cargo xtask docs fold >/dev/null || stop "${included[0]}" "fold falhou na main"
  if [ -n "$(git status --porcelain)" ]; then
    local fb
    fb="queue/fold-$(date +%s)"
    git add -A docs
    git commit --quiet -m "docs: consolida docs/changes (lote ${included[*]})"
    git push --quiet origin "HEAD:refs/heads/$fb"
    local fpr
    fpr=$(gh pr create --base "$base" --head "$fb" \
      --title "docs: consolida docs/changes (lote ${included[*]})" \
      --body "Fold da fila de entrada (scripts/land.sh --batch)." | grep -o '[0-9]*$')
    checks_or_stop "$fpr" "$(git rev-parse HEAD)"
    gh pr merge -R "$repo" "$fpr" --squash --delete-branch --match-head-commit "$(git rev-parse HEAD)" ||
      stop "$fpr" "o merge do fold foi recusado"
    say "  fold #$fpr entrou"
  fi
  cd "$root"
  git worktree remove --force "$wt"
}

serial=("$@")
if [ "$batch" = 1 ]; then
  land_batch "$@"
  serial=("${rest[@]}")
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

  cd "$root"
  git worktree remove --force "$wt"
done

git -C "$root" fetch --quiet origin "$base"
say "fila concluída: $*"
