# Módulos do kernel do CI completo

Um user namespace não carrega módulos: o CI completo (lote da fila e `main`) os carrega antes do
`cargo xtask ci`. **Um arquivo por módulo**: o nome do arquivo é o módulo, o conteúdo é a
variável que passa a valer 1 quando ele carrega, para o teste em netns que precisa dele falhar
em vez de pular. Feature nova cria um arquivo aqui; não edita o `ci.yml` nem uma lista (os dois
conflitavam entre PRs paralelos). O `vrf` tem passo próprio no `ci.yml` (às vezes só existe no
`linux-modules-extra`).
