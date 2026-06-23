RELATÓRIO DE ATAQUE
===================

Time        : Red Team
Data/Hora   : 2026-06-23 05:24
Integrantes : Paulo H., Guilherme, Antônio Vitor, Renângela, Victor, Alex.

1. DESCRIÇÃO DO ATAQUE
   ───────────────────
   Rota explorada  : GET http://localhost:8080/orders/:id
   Método utilizado: Enumeração sequencial de IDs (BOLA — OWASP API1:2023)
   Ferramenta      : Python (requests) — exploit_bola.py

   A API não verifica se o usuário autenticado é o dono do pedido
   solicitado. Qualquer token válido permite acessar pedidos de
   qualquer outro usuário bastando incrementar o ID na URL.

2. EXECUÇÃO
   ────────
   Total de requisições enviadas : 100
   Período de execução           : 05:24 até 05:26 (101.5s)
   IDs testados                  : de 1 até 100
   Pedidos coletados (HTTP 200)  : 7

3. RESULTADOS — ANTES DO HARDENING
   ─────────────────────────────────
   Respostas HTTP 200 : 7 
   Respostas HTTP 404 : 15 
   Respostas HTTP 429 : 78 
   Dados coletados    : [x] JSON  salvos em evidence/pedidos_coletados.json

4. HARDENING IMPLEMENTADO
   ───────────────────────
   Arquivo modificado: proxy/nginx.conf
   Técnica: limit_req_zone (módulo ngx_http_limit_req_module)

   Configuração aplicada:
     limit_req_zone $binary_remote_addr zone=orders:10m rate=10r/m;
     # Na location /orders/:
     limit_req zone=orders burst=5 nodelay;
     limit_req_status 429;

   Rate definido  : 10 requisições por minuto por IP
   Burst definido : 5 (requisições extras toleradas antes do bloqueio)

5. RESULTADOS — APÓS O HARDENING
   ────────────────────────────────
   Respostas HTTP 200 : 7 (Pedidos que deram certo serem coletados)
   Respostas HTTP 404 : 15 (IDs inexistentes ou sem permissão)
   Respostas HTTP 429 : 78 (IDs bloqueados por rate limiting)
   O ataque foi mitigado? [ ] Sim  [x] Parcialmente  [ ] Não

   Observação: o rate limiting reduz a velocidade do ataque mas
   não elimina a vulnerabilidade. O fix correto é validar na API
   se user_id do token == user_id do pedido no banco.

6. CONCLUSÃO
   ──────────
   O rate limiting MITIGA mas não CORRIGE o BOLA. Um atacante
   paciente pode aguardar a janela de reset e continuar a
   enumeração em baixa velocidade, tornando o ataque mais lento
   mas não impossível.

   (Extra) Bypass testado:
   - Rotação de User-Agent: o NGINX bloqueia por IP ($binary_remote_addr),
     portanto mudar o User-Agent não contorna o rate limiting.

   - Múltiplos IPs (ex: proxies/VPN): cada IP tem sua própria zona,
     logo um atacante com IPs distintos pode distribuir a enumeração
     e contornar o limite por IP.

   - Conclusão: controles baseados em IP são insuficientes sem
     validação de autorização na camada de aplicação.
