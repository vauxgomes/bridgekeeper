"""
Analisa o access.log JSON do NGINX (formato definido em proxy/nginx.conf e
docs/observability.md) e responde as perguntas da Fase 1 do guia do Blue Team:

  - Quais IPs fizeram mais requisicoes a /orders/
  - Quantos IDs de pedido distintos cada IP acessou
  - Distribuicao de status HTTP (200, 404, 429) ao longo do tempo
  - Momento de inicio e fim do ataque + tempo de deteccao (MTTD)

Uso:
    python analise_log.py <caminho-do-access.log>

Sem argumento, usa blueteam/evidence/access-log-simulado.log (log de
demonstracao, ja que o ambiente Docker nao estava disponivel para gerar um
access.log real a partir do docker-compose).
"""
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# Limiar de anomalia: trafego legitimo nesta API gira em torno de poucas
# requisicoes por minuto por usuario. Mais de 20 req/min de um unico IP
# em /orders/ e tratado como automacao / enumeracao.
ANOMALY_THRESHOLD_PER_MIN = 20
ORDER_ID_RE = re.compile(r"^/orders/(\d+)$")

# Mapa pedido -> usuario, espelhando api/src/data/seed.ts (unica fonte de
# "quem e o titular dos dados" — o log nao traz isso, so a API teria).
ORDER_TO_USER = {1: 101, 2: 102, 3: 101, 4: 103, 5: 102, 6: 104, 7: 101, 8: 105}


def load_log(path: Path):
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def parse_time(rec):
    return datetime.fromisoformat(rec["time"])


def main():
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "access-log-simulado.log"
    records = load_log(log_path)
    records.sort(key=parse_time)

    orders_reqs = [r for r in records if r["uri"].startswith("/orders/") and r["uri"] != "/orders/"]

    # --- Requisicoes e IDs distintos por IP ---
    reqs_by_ip = defaultdict(int)
    ids_by_ip = defaultdict(set)
    status_by_ip = defaultdict(lambda: defaultdict(int))
    for r in orders_reqs:
        ip = r["remote_addr"]
        reqs_by_ip[ip] += 1
        status_by_ip[ip][r["status"]] += 1
        m = ORDER_ID_RE.match(r["uri"])
        if m:
            ids_by_ip[ip].add(int(m.group(1)))

    # --- Distribuicao geral de status HTTP ---
    status_dist = defaultdict(int)
    for r in orders_reqs:
        status_dist[r["status"]] += 1

    # --- Deteccao de anomalia por IP (janela de 1 minuto) ---
    per_minute = defaultdict(lambda: defaultdict(int))
    for r in orders_reqs:
        bucket = parse_time(r).replace(second=0, microsecond=0)
        per_minute[r["remote_addr"]][bucket] += 1

    anomalous_ips = sorted(
        ip for ip, buckets in per_minute.items()
        if max(buckets.values()) >= ANOMALY_THRESHOLD_PER_MIN
    )

    print("=" * 70)
    print("ANALISE DE LOG -", log_path.name)
    print("=" * 70)

    print(f"\nTotal de requisicoes a /orders/<id>: {len(orders_reqs)}")

    print("\n--- Requisicoes por IP (top 10) ---")
    for ip, count in sorted(reqs_by_ip.items(), key=lambda x: -x[1])[:10]:
        flag = "  <-- ANOMALO" if ip in anomalous_ips else ""
        print(f"  {ip:<16} {count:>5} reqs   {len(ids_by_ip[ip]):>4} IDs distintos{flag}")

    print("\n--- Distribuicao de status HTTP ---")
    for status, count in sorted(status_dist.items()):
        print(f"  {status}: {count}")

    print("\n--- Status HTTP por IP suspeito ---")
    for ip in anomalous_ips:
        dist = ", ".join(f"{s}={c}" for s, c in sorted(status_by_ip[ip].items()))
        print(f"  {ip}: {dist}")

    # --- Janela do ataque e MTTD ---
    print("\n--- Janela de ataque por IP suspeito ---")
    mttd_lines = []
    for ip in anomalous_ips:
        ip_reqs = [r for r in orders_reqs if r["remote_addr"] == ip]
        first_ts = parse_time(ip_reqs[0])
        last_ts = parse_time(ip_reqs[-1])

        # momento em que o volume cumulativo cruza o limiar de anomalia
        running = 0
        window_start = first_ts
        detected_at = last_ts
        for r in ip_reqs:
            ts = parse_time(r)
            running += 1
            if (ts - window_start) > timedelta(minutes=1):
                window_start = ts
                running = 1
            if running >= ANOMALY_THRESHOLD_PER_MIN:
                detected_at = ts
                break

        detection_delta = detected_at - first_ts
        print(f"  {ip}")
        print(f"    inicio  : {first_ts.isoformat()}")
        print(f"    fim     : {last_ts.isoformat()}")
        print(f"    duracao : {last_ts - first_ts}")
        print(f"    deteccao (>= {ANOMALY_THRESHOLD_PER_MIN} req/min) em: {detected_at.isoformat()}"
              f"  (+{detection_delta.total_seconds():.1f}s desde a 1a req)")
        mttd_lines.append((ip, first_ts, detected_at, detection_delta))

    if mttd_lines:
        overall_first = min(x[1] for x in mttd_lines)
        overall_detected = min(x[2] for x in mttd_lines)
        print("\n--- MTTD (Mean Time to Detect) consolidado ---")
        print(f"  1a requisicao anomala em : {overall_first.isoformat()}")
        print(f"  Padrao detectavel em      : {overall_detected.isoformat()}")
        print(f"  MTTD                      : {(overall_detected - overall_first).total_seconds():.1f} segundos"
              f" (~{(overall_detected - overall_first).total_seconds() / 60:.2f} min)")

    # --- Pedidos efetivamente expostos (200) por IP anomalo ---
    print("\n--- Pedidos expostos (HTTP 200) por IP anomalo ---")
    total_exposed_ids = set()
    for ip in anomalous_ips:
        exposed = {i for i in ids_by_ip[ip] if i in ORDER_TO_USER}
        total_exposed_ids |= exposed
        print(f"  {ip}: ids validos acessados = {sorted(exposed)}")
    affected_users = {ORDER_TO_USER[i] for i in total_exposed_ids}
    print(f"  Total de pedidos distintos expostos (todos IPs anomalos): {sorted(total_exposed_ids)}"
          f"  -> {len(total_exposed_ids)} pedidos")
    print(f"  Usuarios (titulares) afetados: {sorted(affected_users)} -> {len(affected_users)} titulares")


if __name__ == "__main__":
    main()
