# Red Team — Exploração e Hardening

**Branch:** `redteam/hardening`

---

## Objetivo

Demonstrar na prática o impacto de uma falha de autorização e, em seguida, implementar a primeira linha de defesa no proxy.

---

## Fase 1 — Exploração (Offensive)

A API expõe um endpoint que retorna pedidos pelo ID. Os IDs são sequenciais e não há verificação de propriedade — qualquer usuário pode acessar o pedido de qualquer outro.

**Sua missão:** escrever um script que enumere automaticamente os IDs da rota `/orders/:id`, colete os dados de todos os pedidos encontrados e salve o resultado como evidência.

O script deve identificar quais pedidos pertencem ao usuário autenticado e quais foram acessados indevidamente.

**Ferramentas sugeridas:** Python (`requests`), Postman (Runner com iteração de IDs), curl.

**Entregáveis:**
- Script de exploração em `redteam/evidence/`
- Relatório de ataque preenchido (ver template abaixo)

> Para um passo a passo rápido de execução, veja `redteam/USO.md`

---

## Fase 2 — Hardening (Defensive)

Com o ataque documentado, implemente rate limiting no NGINX para barrar automações de alta velocidade.

**Sua missão:** configurar o módulo `limit_req_zone` no arquivo `proxy/nginx.conf` para limitar o número de requisições por IP na rota `/orders/`. Após ativar, re-execute o script da Fase 1 e confirme que as respostas HTTP 429 aparecem nos logs.

**Entregáveis:**
- `proxy/nginx.conf` com rate limiting ativo
- Relatório de ataque atualizado com os resultados antes e depois do hardening

---

## Desafio Extra

Após implementar o rate limiting, tente contorná-lo usando cabeçalhos `User-Agent` rotativos ou IPs distintos. O bloqueio por IP é suficiente para impedir o ataque? Documente a conclusão no relatório.

---

## Template — Relatório de Ataque

Salve como `redteam/evidence/relatorio-ataque.md`.

```
RELATÓRIO DE ATAQUE
===================

Time        : Red Team
Data/Hora   : ____-__-__ __:__
Integrantes : ___________________________

1. DESCRIÇÃO DO ATAQUE
   ───────────────────
   Rota explorada  : 
   Método utilizado: 
   Ferramenta      : 

2. EXECUÇÃO
   ────────
   Total de requisições enviadas : 
   Período de execução           : __:__ até __:__
   IDs acessados                 : de ___ até ___
   Pedidos de outros usuários encontrados: ___

3. RESULTADOS — ANTES DO HARDENING
   ─────────────────────────────────
   Respostas HTTP 200 : 
   Respostas HTTP 404 : 
   Dados coletados    : [ ] JSON  [ ] CSV  [ ] Outro: ___

4. HARDENING IMPLEMENTADO
   ───────────────────────
   Configuração aplicada (resumo):

   Rate definido  : 
   Burst definido : 

5. RESULTADOS — APÓS O HARDENING
   ────────────────────────────────
   Respostas HTTP 200 : 
   Respostas HTTP 429 : 
   O ataque foi mitigado? [ ] Sim  [ ] Parcialmente  [ ] Não

6. CONCLUSÃO
   ──────────
   O rate limiting resolve a vulnerabilidade ou apenas a mitiga?

   (Extra) Foi possível contornar o rate limiting? Como?
```

---

## Conceitos para a Apresentação

A apresentação do time deve explicar, no mínimo, os seguintes conceitos:

- **OWASP API Top 10** — o que é, qual a posição do BOLA nessa lista e por que ele é considerado a vulnerabilidade mais crítica em APIs
- **BOLA (Broken Object Level Authorization)** — como a vulnerabilidade funciona tecnicamente: o que falta no código, por que IDs sequenciais agravam o problema e como um atacante a explora
- **LGPD** — o que caracteriza um vazamento de dados pessoais e em quais situações ele precisa ser reportado
- **Rate Limiting** — o que é, como o `limit_req_zone` funciona no NGINX e qual a diferença entre **mitigar** e **corrigir** uma vulnerabilidade
- **Evasão de controles** — o que são técnicas de evasão (ex: rotação de User-Agent) e por que controles baseados apenas em IP têm limitações

---

## Checklist de Entrega

- [ ] Script de exploração em `redteam/evidence/`
- [ ] Relatório de ataque preenchido em `redteam/evidence/`
- [ ] `proxy/nginx.conf` com rate limiting ativo
- [ ] Confirmação de respostas HTTP 429 nos logs
- [ ] (Extra) Documentação da tentativa de bypass no relatório

---

**Techs:** NGINX, Python, Postman.
