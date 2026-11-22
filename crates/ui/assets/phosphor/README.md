# Phosphor Icons (subconjunto)

`Phosphor-subset.ttf`: só os glifos que `crates/ui/src/icons.rs` usa (G0.23), cortados do
`res/Phosphor.ttf` (peso regular) do crate `egui-phosphor` 0.14.0 por
`scripts/icons-subset.sh`. Fonte original: [Phosphor Icons](https://phosphoricons.com),
licença MIT (`LICENSE`, ao lado).

Ícone novo: acrescente a constante em `icons.rs` (nome e código do Phosphor), rode o script com
a fonte completa e faça commit dos dois arquivos. O teste `the_font_has_every_icon` reprova se
faltar um glifo.
