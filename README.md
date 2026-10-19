# Multiplay Educação Standalone

Projeto separado para a plataforma Multiplay Educação. Este repositório não deve conter chamadas ou dependências da Global EAD; a integração e o login único ficam em outro projeto.

## Conteúdo inicial
- `educacao-app.html`: interface de Educação copiada do site Multiplay.
- `catalogo-cursos.html`: página de catálogo.
- `educacao-catalogo-mestre.json`: catálogo mestre de cursos próprios e parceiros.
- `assets/multiplay-educacao-logo.svg`: identidade visual.

## Atenção
Esta é a base de migração do front-end e do catálogo. Antes de publicar para alunos, implementar e testar aqui as rotas próprias de autenticação, cursos, matrículas, aulas, progresso e certificados. Não conectar este projeto ao serviço Global EAD.
