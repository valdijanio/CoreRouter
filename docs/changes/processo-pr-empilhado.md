id: processo

Fila de entrada: resolve sozinha o conflito de **PR empilhado**. Quando a parte seguinte de uma
feature sai da branch da anterior e a anterior entra por squash, a seguinte traz as mudanças dela
duas vezes (os commits originais e o squash na `main`), e o GitHub acusa conflito. A fila agora
confere, arquivo por arquivo, se a `main` tem exatamente o que o PR pai tinha (o pai é um PR já
integrado cujo último commit é ancestral da branch); se sim, fica com o lado do PR (pai + o que
ele mudou), dá push na branch e segue, no lote e no merge da `main` antes do squash. Arquivo que
não bate com o pai continua sendo conflito de verdade, para a sessão dona. Era o que as sessões
faziam à mão, uma volta de CI cada (#112, G4.2b/c, #146, #147 duas vezes, 2026-10-22/23).
`AGENTS.md`: "Pode empilhar". Testado com repositório de mentira: pai integrado por squash e filho
empilhado (resolve, nas duas direções), e main que mudou o mesmo trecho depois (recusa).
