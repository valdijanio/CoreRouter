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
#   - merge limpo: push na branch e aprova o `ci` do PR. O push do bot gera o evento
#     `pull_request`, mas o GitHub o deixa em "Action required" (o bot conta como colaborador
#     novo), e é esse run que o PR enxerga: um `ci` disparado por `workflow_dispatch` passa no
#     commit, mas não conta para o PR (#45 ficou BLOCKED com os três checks verdes). Se o run
#     não aparecer, cai no `workflow_dispatch` antigo e avisa;
#   - conflito de verdade: nada é enviado; comentário no PR (um por commit da main) com os
#     arquivos e o rótulo `conflito`, para a sessão dona resolver; o rótulo sai na próxima
#     execução em que o PR não conflitar mais (inclusive quando a sessão resolveu à mão);
#   - se a branch andou enquanto o merge rodava, não comenta: o aviso seria sobre um commit velho.
#
# Ambiente: GH_TOKEN, GH_REPO; BASE (padrão main); DRY_RUN=1 só diz o que faria.
set -euo pipefail

base=${BASE:-main}
dry=${DRY_RUN:-0}
label="conflito"

repo=${GH_REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}

say() { printf '%s\n' "$*"; }
run() { if [ "$dry" = 1 ]; then say "  (dry-run) $*"; else "$@"; fi; }

# Aprova o run `pull_request` que o push do bot deixou em "Action required" (até ~2 min).
approve_ci() {
  local sha=$1 ids
  [ "$dry" = 1 ] && { say "  (dry-run) aprovaria o ci de $sha"; return 0; }
  for _ in $(seq 1 24); do
    ids=$(gh api "repos/$repo/actions/runs?head_sha=$sha&event=pull_request" \
      --jq '.workflow_runs[] | select(.status == "action_required") | .id')
    if [ -n "$ids" ]; then
      for id in $ids; do
        say "  aprova o ci (run $id)"
        gh api --silent -X POST "repos/$repo/actions/runs/$id/approve" || return 1
      done
      return 0
    fi
    sleep 5
  done
  return 1
}

# Rótulos pela API REST: o `gh pr edit --add-label/--remove-label` falha em versões do gh que
# ainda consultam os Projects clássicos (descontinuados).
label_add() { run gh api --silent -X POST "repos/$repo/issues/$1/labels" -f "labels[]=$label"; }
label_remove() {
  [ "$2" = 1 ] || return 0
  say "  tira o rótulo $label"
  run gh api --silent -X DELETE "repos/$repo/issues/$1/labels/$label" || true
}

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

# shellcheck disable=SC2016 # `\(…)` é interpolação do jq, não do shell
prs=$(gh pr list --base "$base" --state open --limit 100 \
  --json number,headRefName,isCrossRepository,isDraft,autoMergeRequest,labels \
  --jq '.[] | select((.isCrossRepository | not) and (.isDraft | not) and .autoMergeRequest != null)
             | "\(.number) \(.headRefName) \(if any(.labels[]; .name == "'"$label"'") then 1 else 0 end)"')

if [ -z "$prs" ]; then
  say "nenhum PR com auto-merge aberto"
  exit 0
fi

gh label create "$label" --color D93F0B \
  --description "Conflito real com a main: a sessão dona resolve" 2>/dev/null || true

while read -r n branch labeled; do
  [ -z "$n" ] && continue
  state=$(mergeable_of "$n")
  say "#$n ($branch): $state"
  if [ "$state" != CONFLICTING ]; then
    [ "$state" = MERGEABLE ] && label_remove "$n" "$labeled"
    continue
  fi

  git fetch --quiet origin "$branch"
  git checkout --quiet -B "pr-sync/$n" "origin/$branch"
  if git merge-base --is-ancestor "origin/$base" HEAD; then
    say "  já contém a main $short; nada a fazer"
    label_remove "$n" "$labeled"
    continue
  fi

  if git merge --no-edit --quiet "origin/$base" -m "Merge origin/$base ($short) em $branch (pr-sync)"; then
    say "  merge limpo: push e ci"
    # Sem --force: se a sessão dona enviou algo neste meio tempo, o push falha e fica com ela.
    if run git push --quiet origin "HEAD:refs/heads/$branch"; then
      if ! approve_ci "$(git rev-parse HEAD)"; then
        say "  aviso: nenhum ci do PR para aprovar; dispara por workflow_dispatch (pode não contar para o PR)"
        run gh workflow run ci.yml --ref "$branch"
      fi
      label_remove "$n" "$labeled"
    else
      say "  push recusado (a branch andou); fica para o próximo push na main"
    fi
  else
    # shellcheck disable=SC2016 # crases literais: Markdown do comentário
    files=$(git diff --name-only --diff-filter=U | sed 's/^/- `/; s/$/`/')
    git merge --abort
    head=$(gh pr view "$n" --json headRefOid --jq .headRefOid)
    if [ "$head" != "$(git rev-parse HEAD)" ]; then
      say "  a branch andou durante o merge; fica para o próximo push na main"
      continue
    fi
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
    label_add "$n"
  fi
done <<< "$prs"

git checkout --quiet --detach "origin/$base"
