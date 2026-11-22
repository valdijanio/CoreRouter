#!/usr/bin/env bash
# Bateria da fila de entrada: gera a feature sintética N (1..10) na worktree atual.
# Uso (dentro de uma worktree da branch bench/fNN): scripts/bench-queue/gen-feature.sh <N>
#
# Todas: uma área de comandos nova (`bench.fNN.get`), um teste de integração e o arquivo de
# mudança. Algumas imitam o que acontece com features reais em paralelo:
#   7, 8  — os dois acrescentam um campo ao mesmo struct (`System`): conflito de texto;
#   9     — um teste monta `System { identity }` literal: passa sozinho, quebra junto com o 7
#           (o "sozinho passa, junto quebra" do from_pool/Head.parent);
#   10    — o arquivo de mudança traz uma gap nova (caminho de linhas novas do fold);
#   6     — o arquivo de mudança muda o status de uma gap existente.
set -euo pipefail

n=${1:?uso: gen-feature.sh <N>}
nn=$(printf '%02d' "$n")

cat > "crates/engine/src/cmd/bench_f$nn.rs" <<EOF
//! Bateria da fila de entrada (bench/queue): feature sintética $nn.

use serde_json::{Value, json};

use super::{CommandSpec, always};
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "bench.f$nn.get", "Bench $nn", [], None,
    "{} → {identity, n}",
    always, get)];

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(json!({ "identity": s.store().candidate().system.identity, "n": $n }))
}
EOF

cat > "crates/engine/tests/bench_f$nn.rs" <<EOF
//! Bateria da fila de entrada: feature sintética $nn.
#![allow(clippy::unwrap_used)]

use corerouter_engine::Session;
use serde_json::json;

#[test]
fn bench_f${nn}_answers() {
    let mut s = Session::virtual_lab();
    let v = s.execute("bench.f$nn.get", &json!({})).unwrap();
    assert_eq!(v["n"], json!($n));
}
EOF

case "$n" in
  7 | 8)
    field=$([ "$n" = 7 ] && echo location || echo contact)
    python3 - "$field" <<'PY'
import sys
field = sys.argv[1]
p = "crates/model/src/config.rs"
s = open(p).read()
old = "pub struct System {\n    pub identity: String,\n}"
assert s.count(old) == 1
s = s.replace(old, "pub struct System {\n    pub identity: String,\n    pub %s: String,\n}" % field)
old = '            identity: "CoreRouter".into(),\n'
assert s.count(old) == 1
s = s.replace(old, old + "            %s: String::new(),\n" % field)
open(p, "w").write(s)
PY
    ;;
  9)
    cat >> "crates/engine/tests/bench_f$nn.rs" <<'EOF'

#[test]
fn bench_f09_builds_a_system_literal() {
    let s = corerouter_model::System {
        identity: "edge-1".into(),
    };
    assert_eq!(s.identity, "edge-1");
}
EOF
    ;;
esac

id="G9.$n" file="G9.$n"
# 6: muda o status de uma gap que existe (o id do arquivo é o da gap).
[ "$n" = 6 ] && id="G0.5" file="G0.5-bench"
{
  echo "id: $id"
  [ "$n" = 6 ] && echo "status: aberto (bateria da fila: status mudado pelo fold)"
  echo
  echo "Bateria da fila de entrada: feature sintética $nn (\`bench.f$nn.get\`)."
  [ "$n" = 10 ] && echo "| G0.10 | Gap nova da bateria | engine | Linha nova inserida pelo fold depois da G0.9 | 1 h | aberto |"
  true
} > "docs/changes/$file.md"
