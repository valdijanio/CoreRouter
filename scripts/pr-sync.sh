#!/usr/bin/env bash
# Traz a `main` para os PRs abertos com auto-merge que o GitHub marca como CONFLICTING
# (workflow `pr-sync`, AGENTS.md "Integração").
#
# Por quê: o GitHub ignora `merge=union` (.gitattributes) ao calcular se um PR conflita, então
# todo PR vira CONFLICTING quando outro acrescenta ao `docs/log.md` ou `docs/gaps-history.md` —
# e o auto-merge para. Um `git merge` de verdade aplica o union e quase sempre sai limpo.
#
#   - só PRs do próprio repositório, abertos, não rascunho, com auto-merge ligado;
#   - só os que o GitHub diz CONFLICTING (com a proteção sem "branch atualizada", PR mergeável
#     não precisa da main: não gastamos CI à toa);
#   - merge limpo: push na branch e dispara o `ci` nela (push com GITHUB_TOKEN não dispara
#     workflows; `workflow_dispatch` sim) — os checks exigidos rodam no novo commit;
#   - conflito de verdade: nada é enviado; comentário no PR (um por commit da main) com os
#     arquivos e o rótulo `conflito`, para a sessão dona resolver.
#
# Ambiente: GH_TOKEN, GH_REPO; BASE (padrão main); DRY_RUN=1 só diz o que faria.
set -euo pipefail

base=${BASE:-main}
dry=${DRY_RUN:-0}
label="conflito"

say() { printf '%s\n' "$*"; }
run() { if [ "$dry" = 1 ]; then say "  (dry-run) $*"; else "$@"; fi; }

git fetch --quiet origin "$base"
main_sha=$(git rev-parse "origin/$base")
short=${main_sha:0:7}

# O union vale mesmo numa branch criada antes do .gitattributes: usa o da main.
attrs=$(mktemp)
git show "origin/$base:.gitattributes" > "$attrs" 2>/dev/null || true
git config core.attributesFile "$attrs"

# O GitHub calcula `mergeable` depois do push: UNKNOWN até lá.
mergeable_of() {
  local n=$1 m=UNKNOWN
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
    m=$(gh pr view "$n" --json mergeable --jq .mergeable)
    [ "$m" != UNKNOWN ] && break
    sleep 10
  done
  printf '%s' "$m"
}

prs=$(gh pr list --base "$base" --state open --limit 100 \
  --json number,headRefName,isCrossRepository,isDraft,autoMergeRequest \
  --jq '.[] | select((.isCrossRepository | not) and (.isDraft | not) and .autoMergeRequest != null)
             | "\(.number) \(.headRefName)"')

if [ -z "$prs" ]; then
  say "nenhum PR com auto-merge aberto"
  exit 0
fi

gh label create "$label" --color D93F0B \
  --description "Conflito real com a main: a sessão dona resolve" 2>/dev/null || true

while read -r n branch; do
  [ -z "$n" ] && continue
  state=$(mergeable_of "$n")
  say "#$n ($branch): $state"
  [ "$state" = CONFLICTING ] || continue

  git fetch --quiet origin "$branch"
  git checkout --quiet -B "pr-sync/$n" "origin/$branch"
  if git merge-base --is-ancestor "origin/$base" HEAD; then
    say "  já contém a main $short; nada a fazer"
    continue
  fi

  if git merge --no-edit --quiet "origin/$base" -m "Merge origin/$base ($short) em $branch (pr-sync)"; then
    say "  merge limpo: push e ci"
    # Sem --force: se a sessão dona enviou algo neste meio tempo, o push falha e fica com ela.
    if run git push --quiet origin "HEAD:refs/heads/$branch"; then
      run gh workflow run ci.yml --ref "$branch"
      run gh pr edit "$n" --remove-label "$label" >/dev/null 2>&1 || true
    else
      say "  push recusado (a branch andou); fica para o próximo push na main"
    fi
  else
    files=$(git diff --name-only --diff-filter=U | sed 's/^/- `/; s/$/`/')
    git merge --abort
    marker="<!-- pr-sync:$main_sha -->"
    if gh pr view "$n" --json comments --jq '.comments[].body' | grep -qF "$marker"; then
      say "  conflito real (já avisado)"
      continue
    fi
    say "  conflito real: comentário no PR"
    body="$marker
**pr-sync:** a \`$base\` (\`$short\`) conflita de verdade com esta branch nestes arquivos:

$files

Resolva na branch: \`git fetch origin && git merge origin/$base\`, \`cargo xtask ci\`, push (AGENTS.md, \"Integração\")."
    run gh pr comment "$n" --body "$body"
    run gh pr edit "$n" --add-label "$label" >/dev/null
  fi
done <<< "$prs"

git checkout --quiet --detach "origin/$base"
