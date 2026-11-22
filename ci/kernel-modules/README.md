# Módulos do kernel do CI completo

Um user namespace não carrega módulos: o CI completo (lote da fila e `main`) os carrega antes do
`cargo xtask ci`. **Um arquivo por módulo**: o nome do arquivo é o módulo, o conteúdo é a
variável que passa a valer 1 quando ele carrega, para o teste em netns que precisa dele falhar
em vez de pular. Feature nova cria um arquivo aqui; não edita o `ci.yml` nem uma lista (os dois
conflitavam entre PRs paralelos). O `vrf` tem passo próprio no `ci.yml` (às vezes só existe no
`linux-modules-extra`).

Um módulo que o kernel do runner pode não ter (o `mpls_router` não vem no pacote base das
imagens do Azure) leva uma segunda linha `optional`. O setup tenta o `modprobe` e, se falhar, o
`.ko` guardado do `linux-modules-extra` (o mesmo cache do `vrf`). Sem nenhum dos dois, a variável
fica 0 e o teste pula, com aviso no run, em vez de travar a fila.
