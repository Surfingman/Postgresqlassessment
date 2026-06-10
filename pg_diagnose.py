#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pg_diagnose v2 (Level 3) — Azure Database for PostgreSQL Flexible Server 진단 도구

레벨 1~2(수집·탐지)에 더해 레벨 3(상관·근본원인 단서)을 제공한다.
  · 계층 1  Azure Monitor 메트릭            — CPU/메모리/IOPS/스토리지/연결 추세
  · 계층 2  PostgreSQL 엔진 내부 통계        — 쿼리/인덱스/블로트/vacuum/블로킹/파라미터
  · 계층 3a Query Store (azure_sys)         — 시간대별 쿼리 귀속 + 대기 통계
  · 계층 3b EXPLAIN(GENERIC_PLAN, PG16+)    — 상위 쿼리 실행계획 red flag (실행 없이 계획만)
  · 계층 3c 리소스-쿼리 상관                 — CPU 스파이크 시점 → 해당 윈도우 지배 쿼리
  · 계층 3d Baseline 회귀 탐지(JSON 이력)   — 쿼리 평균시간 회귀 / Health Score 추세

안전·견고성:
  · 읽기 전용. 서버를 변경하지 않는다. EXPLAIN 은 ANALYZE 없이 "계획만" 생성(쿼리 미실행).
  · 각 진단/계층은 독립 try/except → 일부 실패(확장 미설치·권한·버전)해도 나머지는 진행.
  · 차트는 인라인 SVG → 인터넷/CDN 없이 열림(폐쇄망·고객사 친화적).

사용 예:
  python pg_diagnose.py --demo --out report.html        # 연결 없이 결과물 미리보기
  python pg_diagnose.py \
     --host <name>.postgres.database.azure.com --dbname appdb --user pgadmin \
     --resource-id "/subscriptions/.../flexibleServers/<name>" --hours 24 --out report.html
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import html
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# ──────────────────────────────────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class Config:
    host: Optional[str] = None
    port: int = 5432
    dbname: str = "postgres"
    user: Optional[str] = None
    password: Optional[str] = None
    sslmode: str = "require"
    use_aad: bool = False
    resource_id: Optional[str] = None
    hours: int = 24
    granularity_min: int = 5
    query_store: bool = True       # 계층 3a (azure_sys 연결)
    explain: bool = True           # 계층 3b (EXPLAIN, PG16+)
    explain_top: int = 5
    history: bool = True           # 계층 3d (baseline 회귀)
    history_dir: str = "./pg_diagnose_history"
    out: str = "pg_report.html"
    demo: bool = False


# ──────────────────────────────────────────────────────────────────────────
# 공통 인증/접속 (AAD 토큰 1회 캐시, dbname 별 conninfo)
# ──────────────────────────────────────────────────────────────────────────
class Auth:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._pwd: Optional[str] = None

    def password(self) -> str:
        if self._pwd is not None:
            return self._pwd
        pwd = self.cfg.password or os.environ.get("PGPASSWORD", "")
        if self.cfg.use_aad and not pwd:
            from azure.identity import DefaultAzureCredential
            cred = DefaultAzureCredential()
            pwd = cred.get_token("https://ossrdbms-aad.database.windows.net/.default").token
        self._pwd = pwd
        return pwd

    def conninfo(self, dbname: str) -> str:
        parts = [f"host={self.cfg.host}", f"port={self.cfg.port}", f"dbname={dbname}",
                 f"user={self.cfg.user}", f"sslmode={self.cfg.sslmode}"]
        p = self.password()
        if p:
            parts.append(f"password={p}")
        return " ".join(parts)


# ──────────────────────────────────────────────────────────────────────────
# 공통 데이터 구조
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class TableResult:
    columns: list[str]
    rows: list[list[Any]]
    error: Optional[str] = None
    note: str = ""


@dataclass
class MetricSeries:
    name: str
    unit: str
    timestamps: list[str]            # 표시용 라벨
    raw_ts: list[Any] = field(default_factory=list)  # 상관용 datetime
    avg: list[Optional[float]] = field(default_factory=list)
    mx: list[Optional[float]] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def avg_overall(self) -> Optional[float]:
        v = [x for x in self.avg if x is not None]
        return round(sum(v) / len(v), 1) if v else None

    @property
    def max_overall(self) -> Optional[float]:
        v = [x for x in self.mx if x is not None]
        return round(max(v), 1) if v else None

    def peak(self) -> tuple[Optional[Any], Optional[float]]:
        """최대값의 (시각, 값) 반환 — 상관 분석에 사용."""
        best_i, best_v = None, None
        for i, x in enumerate(self.mx):
            if x is not None and (best_v is None or x > best_v):
                best_v, best_i = x, i
        if best_i is None:
            return None, None
        ts = self.raw_ts[best_i] if best_i < len(self.raw_ts) else None
        return ts, round(best_v, 1)


@dataclass
class ExplainResult:
    query_id: str
    query: str
    ok: bool
    total_cost: Optional[float] = None
    flags: list[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    recommendation: str


SEV_CRIT, SEV_WARN, SEV_INFO, SEV_OK = "critical", "warning", "info", "ok"
SEV_WEIGHT = {SEV_CRIT: 25, SEV_WARN: 10, SEV_INFO: 2, SEV_OK: 0}
SEV_LABEL = {SEV_CRIT: "위험", SEV_WARN: "주의", SEV_INFO: "정보", SEV_OK: "양호"}


# ──────────────────────────────────────────────────────────────────────────
# 진단 SQL 카탈로그 (계층 2)
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class Diagnostic:
    key: str
    title: str
    category: str
    sql: str
    note: str = ""


def build_query_catalog(version_num: int) -> list[Diagnostic]:
    total_col, mean_col = (("total_exec_time", "mean_exec_time")
                           if version_num >= 130000 else ("total_time", "mean_time"))
    cat: list[Diagnostic] = []

    cat.append(Diagnostic(
        "top_queries", "총 실행시간 상위 쿼리", "쿼리 성능",
        f"""
            SELECT queryid::text AS queryid, calls,
                   round({total_col}::numeric, 1) AS total_ms,
                   round({mean_col}::numeric, 2)  AS mean_ms, rows,
                   round(100.0 * shared_blks_hit
                         / nullif(shared_blks_hit + shared_blks_read, 0), 1) AS cache_hit_pct,
                   left(regexp_replace(query, '\\s+', ' ', 'g'), 200) AS query
            FROM pg_stat_statements
            ORDER BY {total_col} DESC LIMIT 15;
        """,
        "pg_stat_statements 확장이 필요합니다. shared_preload_libraries 에 추가 후 "
        "CREATE EXTENSION 하세요."))

    cat.append(Diagnostic(
        "cache_hit", "데이터베이스 캐시 히트율", "메모리/캐시",
        """
            SELECT datname,
                   round(100.0*blks_hit/nullif(blks_hit+blks_read,0),2) AS cache_hit_pct,
                   xact_commit, xact_rollback, temp_files,
                   pg_size_pretty(temp_bytes) AS temp_bytes
            FROM pg_stat_database
            WHERE datname NOT IN ('template0','template1') AND blks_read+blks_hit > 0
            ORDER BY cache_hit_pct ASC;
        """))

    cat.append(Diagnostic(
        "active_sessions", "활성·장시간 실행 세션", "동시성",
        """
            SELECT pid, usename, datname, state, wait_event_type, wait_event,
                   round(extract(epoch FROM (now()-query_start)))::int AS dur_sec,
                   left(regexp_replace(query,'\\s+',' ','g'),140) AS query
            FROM pg_stat_activity
            WHERE state IS NOT NULL AND state <> 'idle' AND pid <> pg_backend_pid()
            ORDER BY dur_sec DESC NULLS LAST LIMIT 20;
        """))

    cat.append(Diagnostic(
        "blocking", "블로킹 체인 (Blocking locks)", "동시성",
        """
            SELECT blocked.pid AS blocked_pid, blocked.usename AS blocked_user,
                   round(extract(epoch FROM (now()-blocked.query_start)))::int AS blocked_sec,
                   left(regexp_replace(blocked.query,'\\s+',' ','g'),100) AS blocked_query,
                   blocking.pid AS blocking_pid,
                   left(regexp_replace(blocking.query,'\\s+',' ','g'),100) AS blocking_query
            FROM pg_stat_activity blocked
            JOIN pg_stat_activity blocking
              ON blocking.pid = ANY(pg_blocking_pids(blocked.pid))
            WHERE cardinality(pg_blocking_pids(blocked.pid)) > 0;
        """))

    cat.append(Diagnostic(
        "unused_indexes", "미사용 인덱스", "인덱스",
        """
            SELECT schemaname, relname AS table_name, indexrelname AS index_name, idx_scan,
                   pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
            FROM pg_stat_user_indexes
            WHERE idx_scan = 0
              AND indexrelid NOT IN (SELECT conindid FROM pg_constraint WHERE contype IN ('p','u'))
            ORDER BY pg_relation_size(indexrelid) DESC LIMIT 20;
        """))

    cat.append(Diagnostic(
        "dead_tuples", "Dead tuple · autovacuum 상태", "유지보수",
        """
            SELECT schemaname, relname AS table_name, n_live_tup, n_dead_tup,
                   round(100.0*n_dead_tup/nullif(n_live_tup+n_dead_tup,0),1) AS dead_pct,
                   last_autovacuum, last_autoanalyze
            FROM pg_stat_user_tables
            WHERE n_dead_tup > 0 ORDER BY n_dead_tup DESC LIMIT 20;
        """))

    cat.append(Diagnostic(
        "seq_scans", "Sequential scan 과다 테이블 (인덱스 후보)", "인덱스",
        """
            SELECT schemaname, relname AS table_name, seq_scan, idx_scan,
                   seq_tup_read, n_live_tup, pg_size_pretty(pg_relation_size(relid)) AS table_size
            FROM pg_stat_user_tables
            WHERE seq_scan > 0 AND n_live_tup > 10000
            ORDER BY seq_tup_read DESC LIMIT 15;
        """))

    cat.append(Diagnostic(
        "connections", "연결 상태 요약", "동시성",
        """
            SELECT count(*) AS total,
                   count(*) FILTER (WHERE state='active') AS active,
                   count(*) FILTER (WHERE state='idle') AS idle,
                   count(*) FILTER (WHERE state='idle in transaction') AS idle_in_txn,
                   (SELECT setting::int FROM pg_settings WHERE name='max_connections') AS max_connections
            FROM pg_stat_activity;
        """))

    cat.append(Diagnostic(
        "parameters", "주요 서버 파라미터", "구성",
        """
            SELECT name, setting, unit, source FROM pg_settings
            WHERE name IN ('shared_buffers','effective_cache_size','work_mem',
              'maintenance_work_mem','max_connections','random_page_cost',
              'effective_io_concurrency','max_parallel_workers',
              'max_parallel_workers_per_gather','autovacuum',
              'autovacuum_vacuum_scale_factor','max_wal_size','checkpoint_completion_target')
            ORDER BY name;
        """))

    cat.append(Diagnostic(
        "db_sizes", "데이터베이스 크기", "스토리지",
        """
            SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size
            FROM pg_database WHERE datname NOT IN ('template0','template1')
            ORDER BY pg_database_size(datname) DESC;
        """))

    cp = ("""
            SELECT num_timed AS checkpoints_timed, num_requested AS checkpoints_req,
                   round(write_time::numeric,0) AS write_time_ms,
                   round(sync_time::numeric,0)  AS sync_time_ms, buffers_written
            FROM pg_stat_checkpointer;
         """ if version_num >= 170000 else """
            SELECT checkpoints_timed, checkpoints_req,
                   round(checkpoint_write_time::numeric,0) AS write_time_ms,
                   round(checkpoint_sync_time::numeric,0)  AS sync_time_ms,
                   buffers_checkpoint AS buffers_written
            FROM pg_stat_bgwriter;
         """)
    cat.append(Diagnostic("checkpoints", "체크포인트 통계", "유지보수", cp))
    return cat


# 실행계획을 EXPLAIN 할 수 있는 문장 유형(읽기 전용 계획 생성에 안전)
_EXPLAINABLE = re.compile(r"^\s*(select|with|insert|update|delete|merge|values)\b", re.I)


# ──────────────────────────────────────────────────────────────────────────
# 계층 2 수집기 — PostgreSQL 엔진 (+ EXPLAIN)
# ──────────────────────────────────────────────────────────────────────────
class EngineCollector:
    def __init__(self, cfg: Config, auth: Auth):
        self.cfg = cfg
        self.auth = auth
        self.version_num = 0
        self.version_str = ""

    def collect(self) -> tuple[dict[str, TableResult], list[ExplainResult]]:
        import psycopg
        results: dict[str, TableResult] = {}
        explains: list[ExplainResult] = []
        with psycopg.connect(self.auth.conninfo(self.cfg.dbname),
                             autocommit=True, connect_timeout=15) as conn:
            with conn.cursor() as cur:
                cur.execute("SHOW server_version;")
                self.version_str = cur.fetchone()[0]
                cur.execute("SELECT current_setting('server_version_num')::int;")
                self.version_num = cur.fetchone()[0]

            for d in build_query_catalog(self.version_num):
                try:
                    with conn.cursor() as cur:
                        cur.execute(d.sql)
                        cols = [c.name for c in cur.description]
                        rows = [list(r) for r in cur.fetchall()]
                        results[d.key] = TableResult(cols, rows, note=d.note)
                except Exception as e:  # noqa: BLE001
                    results[d.key] = TableResult([], [], error=str(e).strip(), note=d.note)

            # 계층 3b — EXPLAIN(GENERIC_PLAN). PG16+ 에서 $1 플레이스홀더 그대로 계획 가능.
            if self.cfg.explain and self.version_num >= 160000:
                explains = self._explain_top(conn, results.get("top_queries"))
        return results, explains

    def _explain_top(self, conn, top: Optional[TableResult]) -> list[ExplainResult]:
        out: list[ExplainResult] = []
        if not top or top.error or not top.rows:
            return out
        qi = top.columns.index("query") if "query" in top.columns else None
        idi = top.columns.index("queryid") if "queryid" in top.columns else None
        for r in top.rows[: self.cfg.explain_top]:
            q = r[qi] if qi is not None else None
            qid = str(r[idi]) if idi is not None else "?"
            if not q or not _EXPLAINABLE.match(q):
                continue
            try:
                with conn.cursor() as cur:
                    # EXPLAIN(ANALYZE 미사용) → 쿼리를 실행하지 않고 계획만 생성한다.
                    cur.execute(f"EXPLAIN (GENERIC_PLAN, FORMAT JSON) {q}")
                    plan = cur.fetchone()[0]
                    cost, flags = parse_plan(plan)
                    out.append(ExplainResult(qid, q, True, cost, flags))
            except Exception as e:  # noqa: BLE001 — 잘림/미지원 문장 등
                out.append(ExplainResult(qid, q, False, error=str(e).strip().splitlines()[0]))
        return out


def parse_plan(plan_json: Any) -> tuple[Optional[float], list[str]]:
    """EXPLAIN FORMAT JSON 결과에서 red flag 추출."""
    try:
        root = plan_json[0]["Plan"]
    except Exception:  # noqa: BLE001
        return None, []
    flags: list[str] = []
    seq: list[tuple[str, int]] = []
    total_cost = root.get("Total Cost")

    def walk(node: dict):
        if node.get("Node Type") == "Seq Scan":
            seq.append((node.get("Relation Name", "?"), int(node.get("Plan Rows", 0))))
        for ch in node.get("Plans", []) or []:
            walk(ch)
    walk(root)

    for rel, rows in seq:
        if rows >= 10000:
            flags.append(f"대형 Seq Scan: {rel} (≈{rows:,} rows) — 인덱스 후보")
        else:
            flags.append(f"Seq Scan: {rel} (≈{rows:,} rows)")
    if total_cost and total_cost >= 100000:
        flags.append(f"높은 추정 비용 (Total Cost {total_cost:,.0f})")
    return total_cost, flags


# ──────────────────────────────────────────────────────────────────────────
# 계층 1 수집기 — Azure Monitor
# ──────────────────────────────────────────────────────────────────────────
AZURE_METRICS = [("cpu_percent", "%"), ("memory_percent", "%"), ("iops", "count"),
                 ("storage_percent", "%"), ("active_connections", "count")]


class AzureMetricsCollector:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def collect(self) -> dict[str, MetricSeries]:
        from azure.identity import DefaultAzureCredential
        from azure.monitor.query import MetricsQueryClient, MetricAggregationType
        client = MetricsQueryClient(DefaultAzureCredential())
        out: dict[str, MetricSeries] = {}
        names = [n for n, _ in AZURE_METRICS]
        try:
            resp = client.query_resource(
                self.cfg.resource_id, metric_names=names,
                timespan=dt.timedelta(hours=self.cfg.hours),
                granularity=dt.timedelta(minutes=self.cfg.granularity_min),
                aggregations=[MetricAggregationType.AVERAGE, MetricAggregationType.MAXIMUM])
        except Exception as e:  # noqa: BLE001
            for n, u in AZURE_METRICS:
                out[n] = MetricSeries(n, u, [], error=str(e).strip())
            return out
        um = dict(AZURE_METRICS)
        for m in resp.metrics:
            ts, raw, avg, mx = [], [], [], []
            for s in m.timeseries:
                for dp in s.data:
                    ts.append(dp.timestamp.strftime("%m-%d %H:%M"))
                    raw.append(dp.timestamp)
                    avg.append(dp.average)
                    mx.append(dp.maximum)
            out[m.name] = MetricSeries(m.name, um.get(m.name, ""), ts, raw, avg, mx)
        return out


# ──────────────────────────────────────────────────────────────────────────
# 계층 3a 수집기 — Query Store (azure_sys)
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class QueryStoreData:
    enabled: bool = False
    error: Optional[str] = None
    top: Optional[TableResult] = None          # 기간 전체 상위 쿼리
    windows: Optional[TableResult] = None      # 15분 윈도우별 총부하 (상관용)
    waits: Optional[TableResult] = None        # 대기 통계
    # 상관용 원본 윈도우: [(start_dt, end_dt, total_ms)]
    window_rows: list[tuple[Any, Any, float]] = field(default_factory=list)


class QueryStoreCollector:
    def __init__(self, cfg: Config, auth: Auth):
        self.cfg = cfg
        self.auth = auth

    def collect(self) -> QueryStoreData:
        import psycopg
        d = QueryStoreData()
        try:
            with psycopg.connect(self.auth.conninfo("azure_sys"),
                                 autocommit=True, connect_timeout=15) as conn:
                # 캡처 모드 확인 (none 이면 사실상 비활성)
                with conn.cursor() as cur:
                    try:
                        cur.execute("SELECT current_setting('pg_qs.query_capture_mode');")
                        mode = cur.fetchone()[0]
                    except Exception:  # noqa: BLE001
                        mode = "unknown"
                if mode == "none":
                    d.error = ("pg_qs.query_capture_mode = none (Query Store 비활성). "
                               "서버 파라미터를 top/all 로 설정하세요. (Burstable 티어 제외)")
                    return d
                d.enabled = True

                # 기간 전체 상위 쿼리
                d.top = self._q(conn, """
                    SELECT query_id::text AS query_id, sum(calls) AS calls,
                           round(sum(total_time)::numeric,1) AS total_ms,
                           round((sum(total_time)/nullif(sum(calls),0))::numeric,2) AS mean_ms,
                           round(max(max_time)::numeric,1) AS max_ms,
                           left(regexp_replace(min(query_sql_text),'\\s+',' ','g'),180) AS query
                    FROM query_store.qs_view
                    WHERE start_time >= now()::timestamp - make_interval(hours => %s)
                    GROUP BY query_id ORDER BY total_ms DESC LIMIT 15;
                """, (self.cfg.hours,))

                # 윈도우별 총부하 (상관 + 시계열)
                d.windows = self._q(conn, """
                    SELECT start_time, end_time,
                           round(sum(total_time)::numeric,1) AS window_total_ms,
                           sum(calls) AS window_calls
                    FROM query_store.qs_view
                    WHERE start_time >= now()::timestamp - make_interval(hours => %s)
                    GROUP BY start_time, end_time ORDER BY start_time;
                """, (self.cfg.hours,))
                if d.windows and not d.windows.error:
                    for r in d.windows.rows:
                        try:
                            d.window_rows.append((r[0], r[1], float(r[2] or 0)))
                        except Exception:  # noqa: BLE001
                            pass

                # 대기 통계
                d.waits = self._q(conn, """
                    SELECT event_type, event, sum(calls) AS samples,
                           count(DISTINCT query_id) AS distinct_queries
                    FROM query_store.pgms_wait_sampling_view
                    GROUP BY event_type, event ORDER BY samples DESC LIMIT 15;
                """, None)
        except Exception as e:  # noqa: BLE001
            d.error = str(e).strip()
        return d

    @staticmethod
    def _q(conn, sql: str, params) -> TableResult:
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                cols = [c.name for c in cur.description]
                rows = [list(r) for r in cur.fetchall()]
                return TableResult(cols, rows)
        except Exception as e:  # noqa: BLE001
            return TableResult([], [], error=str(e).strip().splitlines()[0])

    def window_top_queries(self, ts) -> Optional[TableResult]:
        """특정 시각(ts)을 포함하는 윈도우의 지배 쿼리 — 상관 분석용."""
        import psycopg
        try:
            with psycopg.connect(self.auth.conninfo("azure_sys"),
                                 autocommit=True, connect_timeout=15) as conn:
                return self._q(conn, """
                    SELECT query_id::text AS query_id, sum(calls) AS calls,
                           round(sum(total_time)::numeric,1) AS total_ms,
                           round(max(mean_time)::numeric,2) AS mean_ms,
                           left(regexp_replace(min(query_sql_text),'\\s+',' ','g'),140) AS query
                    FROM query_store.qs_view
                    WHERE %s >= start_time AND %s < end_time
                    GROUP BY query_id ORDER BY total_ms DESC LIMIT 8;
                """, (ts, ts))
        except Exception as e:  # noqa: BLE001
            return TableResult([], [], error=str(e).strip().splitlines()[0])


# ──────────────────────────────────────────────────────────────────────────
# 계층 3c — 상관 (CPU 스파이크 → Query Store 윈도우)
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class Correlation:
    available: bool = False
    note: str = ""
    spike_time: str = ""
    spike_cpu: Optional[float] = None
    window_top: Optional[TableResult] = None


def build_correlation(metrics: dict[str, MetricSeries], qs: QueryStoreData,
                      qs_collector: Optional[QueryStoreCollector],
                      demo_window: Optional[TableResult] = None) -> Correlation:
    c = Correlation()
    cpu = metrics.get("cpu_percent")
    if not cpu or cpu.error:
        c.note = "Azure Monitor CPU 데이터 없음 → 상관 분석 생략."
        return c
    ts, val = cpu.peak()
    if ts is None:
        c.note = "CPU 피크 시점을 찾지 못했습니다."
        return c
    c.spike_time = ts.strftime("%m-%d %H:%M") if hasattr(ts, "strftime") else str(ts)
    c.spike_cpu = val

    if demo_window is not None:                      # 데모: 합성 윈도우
        c.available = True
        c.window_top = demo_window
        c.note = "시각은 UTC 기준 추정입니다(서버 timezone 확인 권장)."
        return c

    if not qs.enabled or qs_collector is None:
        c.note = "Query Store 비활성 → 스파이크 시점 쿼리 귀속 불가."
        return c

    # Azure Monitor 타임스탬프는 UTC(aware). Query Store start/end 는 timestamp(서버 TZ).
    # 서버 TZ=UTC 가정 하에 naive UTC 로 변환해 비교한다(아래 note 로 명시).
    try:
        naive = ts.astimezone(dt.timezone.utc).replace(tzinfo=None) if ts.tzinfo else ts
    except Exception:  # noqa: BLE001
        naive = ts
    c.window_top = qs_collector.window_top_queries(naive)
    c.available = c.window_top is not None and not c.window_top.error and bool(c.window_top.rows)
    c.note = ("시각은 UTC 기준입니다. 서버 timezone 이 UTC 가 아니면 윈도우 정합을 "
              "확인하세요(pg_qs 는 서버 로컬 timestamp 저장).")
    return c


# ──────────────────────────────────────────────────────────────────────────
# 계층 3d — Baseline 이력/회귀
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class RegressionReport:
    has_baseline: bool = False
    baseline_at: str = ""
    score_prev: Optional[int] = None
    score_now: Optional[int] = None
    regressed: list[dict] = field(default_factory=list)   # {query_id, prev_ms, now_ms, delta_pct, query}
    note: str = ""


def _safe_host(host: Optional[str]) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", host or "demo")


def collect_top_query_map(qs: QueryStoreData, engine: dict[str, TableResult]) -> dict[str, dict]:
    """회귀 비교용 쿼리 맵. Query Store(재시작에도 안정적인 query_id) 우선, 없으면 pg_stat_statements."""
    out: dict[str, dict] = {}
    src = qs.top if (qs.enabled and qs.top and not qs.top.error and qs.top.rows) else None
    if src:
        ci = {c: i for i, c in enumerate(src.columns)}
        for r in src.rows:
            qid = str(r[ci["query_id"]])
            out[qid] = {"mean_ms": float(r[ci["mean_ms"]] or 0),
                        "calls": int(r[ci["calls"]] or 0),
                        "total_ms": float(r[ci["total_ms"]] or 0),
                        "query": r[ci["query"]]}
        return out
    t = engine.get("top_queries")
    if t and not t.error and t.rows:
        ci = {c: i for i, c in enumerate(t.columns)}
        for r in t.rows:
            qid = str(r[ci["queryid"]])
            out[qid] = {"mean_ms": float(r[ci["mean_ms"]] or 0),
                        "calls": int(r[ci["calls"]] or 0),
                        "total_ms": float(r[ci["total_ms"]] or 0),
                        "query": r[ci["query"]]}
    return out


def load_baseline(cfg: Config) -> Optional[dict]:
    if not cfg.history:
        return None
    pat = os.path.join(cfg.history_dir, f"{_safe_host(cfg.host)}__*.json")
    files = sorted(glob.glob(pat))
    if not files:
        return None
    try:
        with open(files[-1], encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return None


def save_snapshot(cfg: Config, version: str, score: int,
                  metrics: dict[str, MetricSeries], engine: dict[str, TableResult],
                  qmap: dict[str, dict], cache_min: Optional[float]):
    if not cfg.history or cfg.demo:
        return
    os.makedirs(cfg.history_dir, exist_ok=True)
    snap = {
        "schema_version": 1,
        "host": cfg.host,
        "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version": version,
        "health_score": score,
        "cache_hit_min": cache_min,
        "metrics": {n: {"avg": m.avg_overall, "max": m.max_overall}
                    for n, m in metrics.items() if not m.error},
        "top_queries": {k: {"mean_ms": v["mean_ms"], "calls": v["calls"],
                            "total_ms": v["total_ms"]} for k, v in qmap.items()},
    }
    fn = os.path.join(cfg.history_dir,
                      f"{_safe_host(cfg.host)}__{dt.datetime.now():%Y%m%d_%H%M%S}.json")
    try:
        with open(fn, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, ensure_ascii=False, indent=2)
    except Exception:  # noqa: BLE001
        pass


def compute_regressions(baseline: Optional[dict], qmap: dict[str, dict],
                        score_now: int) -> RegressionReport:
    rr = RegressionReport(score_now=score_now)
    if not baseline:
        rr.note = "이전 스냅샷이 없어 baseline 비교를 생략합니다(다음 실행부터 추세 비교)."
        return rr
    rr.has_baseline = True
    rr.baseline_at = baseline.get("generated_at", "")
    rr.score_prev = baseline.get("health_score")
    prev = baseline.get("top_queries", {})
    for qid, cur in qmap.items():
        p = prev.get(qid)
        if not p:
            continue
        pm, cm = float(p.get("mean_ms", 0)), float(cur.get("mean_ms", 0))
        if pm > 0 and cm >= pm * 1.5 and (cm - pm) >= 5:   # 50%↑ & 절대 5ms↑
            rr.regressed.append({
                "query_id": qid, "prev_ms": round(pm, 2), "now_ms": round(cm, 2),
                "delta_pct": round(100 * (cm - pm) / pm), "query": cur.get("query", "")})
    rr.regressed.sort(key=lambda x: x["delta_pct"], reverse=True)
    return rr


# ──────────────────────────────────────────────────────────────────────────
# 분석기 — 발견사항(Findings)
# ──────────────────────────────────────────────────────────────────────────
def _ci(t: TableResult, name: str) -> Optional[int]:
    return t.columns.index(name) if name in t.columns else None


class Analyzer:
    def __init__(self, engine, metrics, qs: QueryStoreData,
                 explains: list[ExplainResult], regr: RegressionReport):
        self.engine = engine
        self.metrics = metrics
        self.qs = qs
        self.explains = explains
        self.regr = regr
        self.findings: list[Finding] = []

    def run(self) -> list[Finding]:
        self._cache_hit(); self._blocking(); self._dead_tuples(); self._unused_indexes()
        self._connections(); self._long_running(); self._work_mem_temp()
        self._azure_cpu(); self._azure_memory(); self._azure_storage()
        self._regressions(); self._plan_flags(); self._waits()
        if not self.findings:
            self.findings.append(Finding(SEV_OK, "전반", "특이 위험 없음",
                "수집 항목에서 즉각적 임계치 초과가 없습니다.",
                "정기 진단을 스케줄링해 추세를 추적하세요."))
        order = {SEV_CRIT: 0, SEV_WARN: 1, SEV_INFO: 2, SEV_OK: 3}
        self.findings.sort(key=lambda f: order[f.severity])
        return self.findings

    def _cache_hit(self):
        t = self.engine.get("cache_hit")
        if not t or t.error or not t.rows:
            return
        ci, di = _ci(t, "cache_hit_pct"), _ci(t, "datname")
        for r in t.rows:
            pct = float(r[ci]) if r[ci] is not None else 100.0
            if pct < 90:
                self.findings.append(Finding(SEV_CRIT, "메모리/캐시",
                    f"'{r[di]}' 캐시 히트율 {pct}%",
                    f"디스크 읽기 비중이 높습니다(히트율 {pct}%).",
                    "Memory Optimized SKU 검토, shared_buffers/effective_cache_size 점검, "
                    "핫 데이터 인덱싱/파티셔닝."))
            elif pct < 99:
                self.findings.append(Finding(SEV_WARN, "메모리/캐시",
                    f"'{r[di]}' 캐시 히트율 {pct}%",
                    f"OLTP 권장치(≈99%)보다 낮습니다.",
                    "메모리 여유 및 빈번 쿼리의 인덱스 적중을 확인하세요."))

    def _blocking(self):
        t = self.engine.get("blocking")
        if t and not t.error and t.rows:
            self.findings.append(Finding(SEV_CRIT, "동시성",
                f"블로킹 락 {len(t.rows)}건",
                "다른 세션을 대기시키는 락 경합이 있습니다.",
                "blocking_pid 트랜잭션 확인, 필요 시 pg_terminate_backend(). "
                "애플리케이션의 긴 트랜잭션을 점검하세요."))

    def _dead_tuples(self):
        t = self.engine.get("dead_tuples")
        if not t or t.error or not t.rows:
            return
        pi, ni = _ci(t, "dead_pct"), _ci(t, "table_name")
        hot = [(r[ni], float(r[pi])) for r in t.rows
               if pi is not None and r[pi] is not None and float(r[pi]) >= 20]
        if hot:
            worst = ", ".join(f"{n}({p}%)" for n, p in hot[:5])
            self.findings.append(Finding(SEV_WARN, "유지보수",
                f"Dead tuple 비율 높은 테이블 {len(hot)}개",
                f"20%↑: {worst}. 스캔 비용 증가·플래너 추정 오류를 유발합니다.",
                "VACUUM (ANALYZE) 수행. 갱신 잦으면 테이블별 autovacuum_vacuum_scale_factor 하향."))

    def _unused_indexes(self):
        t = self.engine.get("unused_indexes")
        if t and not t.error and t.rows:
            self.findings.append(Finding(SEV_INFO, "인덱스",
                f"미사용 인덱스 {len(t.rows)}개",
                "idx_scan=0 인덱스는 스토리지를 점유하고 쓰기 성능을 떨어뜨립니다.",
                "충분한 관찰 기간(예: 1개월+) 확인 후 DROP INDEX CONCURRENTLY."))

    def _connections(self):
        t = self.engine.get("connections")
        if not t or t.error or not t.rows:
            return
        r = t.rows[0]
        total, maxc, iit = r[_ci(t, "total")], r[_ci(t, "max_connections")], r[_ci(t, "idle_in_txn")]
        if maxc and total and total / maxc >= 0.8:
            self.findings.append(Finding(SEV_WARN, "동시성",
                f"연결 사용률 {round(100*total/maxc)}% ({total}/{maxc})",
                "max_connections 한계 근접 — 신규 연결 거부 위험.",
                "내장 PgBouncer(연결 풀링) 검토, 애플리케이션 풀 크기 점검."))
        if iit and iit >= 5:
            self.findings.append(Finding(SEV_WARN, "동시성",
                f"'idle in transaction' {iit}개",
                "미커밋 트랜잭션이 락·vacuum(xmin horizon)을 막을 수 있습니다.",
                "idle_in_transaction_session_timeout 설정, 커밋 누락 점검."))

    def _long_running(self):
        t = self.engine.get("active_sessions")
        if not t or t.error or not t.rows:
            return
        di = _ci(t, "dur_sec")
        longq = [r for r in t.rows if di is not None and r[di] and r[di] >= 60]
        if longq:
            self.findings.append(Finding(SEV_WARN, "쿼리 성능",
                f"60초↑ 실행 세션 {len(longq)}개",
                "장시간 쿼리가 CPU/락/스냅샷을 점유합니다.",
                "EXPLAIN (ANALYZE, BUFFERS) 로 계획 확인 후 인덱스/쿼리 튜닝."))

    def _work_mem_temp(self):
        p, c = self.engine.get("parameters"), self.engine.get("cache_hit")
        if not p or p.error:
            return
        wm = next((r for r in p.rows if r[_ci(p, "name")] == "work_mem"), None)
        temp = 0
        if c and not c.error and _ci(c, "temp_files") is not None:
            temp = sum(int(r[_ci(c, "temp_files")]) for r in c.rows if r[_ci(c, "temp_files")])
        if temp > 0 and wm is not None:
            self.findings.append(Finding(SEV_INFO, "구성",
                f"임시 파일 생성 {temp}건",
                f"정렬/해시가 work_mem({wm[_ci(p,'setting')]}{wm[_ci(p,'unit')] or ''})를 "
                "초과해 디스크 임시 파일을 사용 중입니다.",
                "대상 쿼리 식별 후 세션/롤 단위 work_mem 점진 상향 또는 쿼리 최적화."))

    def _azure_cpu(self):
        m = self.metrics.get("cpu_percent")
        if not m or m.error:
            return
        mx, avg = m.max_overall, m.avg_overall
        if mx is not None and mx >= 90:
            self.findings.append(Finding(
                SEV_CRIT if (avg or 0) >= 70 else SEV_WARN, "리소스(Azure)",
                f"CPU 최대 {mx}% (평균 {avg}%)",
                "CPU 포화는 쿼리 지연·연결 적체로 확산됩니다.",
                "상관 분석/Query Store 로 상위 CPU 쿼리 식별 → 튜닝. 지속 포화 시 vCore 상향."))

    def _azure_memory(self):
        m = self.metrics.get("memory_percent")
        if m and not m.error and (m.max_overall or 0) >= 85:
            self.findings.append(Finding(SEV_WARN, "리소스(Azure)",
                f"메모리 최대 {m.max_overall}% (평균 {m.avg_overall}%)",
                "메모리 압박은 캐시 효율 저하·OOM 위험을 높입니다.",
                "work_mem×연결 수 합산 점검, 필요 시 Memory Optimized SKU."))

    def _azure_storage(self):
        m = self.metrics.get("storage_percent")
        if not m or m.error:
            return
        mx = m.max_overall
        if mx is not None and mx >= 90:
            self.findings.append(Finding(SEV_CRIT, "리소스(Azure)",
                f"스토리지 사용률 {mx}%",
                "소진 시 서버가 읽기 전용 전환 → 장애.",
                "Storage autogrow 활성화 또는 증설, 블로트 정리."))
        elif mx is not None and mx >= 75:
            self.findings.append(Finding(SEV_WARN, "리소스(Azure)",
                f"스토리지 사용률 {mx}%",
                "여유 감소(IOPS 한도는 용량 연동).",
                "Storage autogrow 설정 및 추세 모니터링."))

    def _regressions(self):
        for r in self.regr.regressed:
            self.findings.append(Finding(SEV_WARN, "회귀(Baseline)",
                f"쿼리 {r['query_id']} 평균시간 +{r['delta_pct']}%",
                f"이전 {r['prev_ms']}ms → 현재 {r['now_ms']}ms. "
                f"({r['query'][:80]})",
                "데이터 증가/통계 노후/계획 변경 가능성. ANALYZE 후 EXPLAIN 비교, "
                "인덱스·파라미터 변화를 점검하세요."))

    def _plan_flags(self):
        for e in self.explains:
            if e.ok and any("인덱스 후보" in f for f in e.flags):
                seq = next(f for f in e.flags if "인덱스 후보" in f)
                self.findings.append(Finding(SEV_INFO, "실행계획",
                    f"쿼리 {e.query_id}: {seq}",
                    f"GENERIC_PLAN 상 대형 순차 스캔이 잡힙니다. ({e.query[:80]})",
                    "필터/조인 컬럼에 인덱스 검토. EXPLAIN(ANALYZE) 로 실제 행수 확인 후 결정."))

    def _waits(self):
        t = self.qs.waits if self.qs.enabled else None
        if not t or t.error or not t.rows:
            return
        si = _ci(t, "samples")
        eti, ei = _ci(t, "event_type"), _ci(t, "event")
        total = sum(int(r[si]) for r in t.rows if r[si]) or 1
        top = t.rows[0]
        share = 100 * int(top[si]) / total
        if share >= 40 and top[eti] not in (None, "", "Cpu", "CPU"):
            self.findings.append(Finding(SEV_INFO, "대기(Query Store)",
                f"지배적 대기: {top[eti]}/{top[ei]} ({share:.0f}%)",
                "전체 대기 샘플의 큰 비중을 한 이벤트가 차지합니다.",
                {"IO": "물리 읽기 과다 → 인덱싱/캐시 검토.",
                 "Lock": "락 경합 → 트랜잭션 짧게/격리수준 조정.",
                 "LWLock": "내부 경합 → 워크로드 분산/버전 점검."}.get(
                     str(top[eti]), "해당 대기 이벤트의 원인 쿼리를 Query Store 에서 추적하세요.")))


def health_score(findings: list[Finding]) -> int:
    return max(0, min(100, 100 - sum(SEV_WEIGHT.get(f.severity, 0) for f in findings)))


# ──────────────────────────────────────────────────────────────────────────
# HTML 리포터
# ──────────────────────────────────────────────────────────────────────────
def _esc(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def _sparkline(values, color, w=220, h=40) -> str:
    pts = [v for v in values if v is not None]
    if len(pts) < 2:
        return '<span class="muted">데이터 없음</span>'
    lo, hi = min(pts), max(pts)
    span = (hi - lo) or 1
    n = len(values)
    coords = []
    for i, v in enumerate(values):
        if v is None:
            continue
        x = i / (n - 1) * (w - 4) + 2
        y = h - 2 - (v - lo) / span * (h - 6)
        coords.append(f"{x:.1f},{y:.1f}")
    return (f'<svg class="spark" viewBox="0 0 {w} {h}" preserveAspectRatio="none">'
            f'<polyline points="{" ".join(coords)}" fill="none" stroke="{color}" '
            f'stroke-width="1.6"/></svg>')


def _table(t: Optional[TableResult]) -> str:
    if t is None:
        return '<p class="muted">수집되지 않음</p>'
    if t.error:
        note = f'<p class="note">{_esc(t.note)}</p>' if t.note else ""
        return f'<p class="err">수집 실패: {_esc(t.error)}</p>{note}'
    if not t.rows:
        return '<p class="muted">해당 항목 없음 (정상이거나 데이터 없음)</p>'
    head = "".join(f"<th>{_esc(c)}</th>" for c in t.columns)
    body = "".join("<tr>" + "".join(f"<td>{_esc(c)}</td>" for c in r) + "</tr>" for r in t.rows)
    return f'<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def render_html(cfg, version_str, engine, metrics, qs: QueryStoreData,
                explains: list[ExplainResult], corr: Correlation,
                regr: RegressionReport, findings, generated_at) -> str:
    score = health_score(findings)
    score_label = "양호" if score >= 85 else ("주의" if score >= 60 else "위험")
    score_cls = SEV_OK if score >= 85 else (SEV_WARN if score >= 60 else SEV_CRIT)
    nc = sum(1 for f in findings if f.severity == SEV_CRIT)
    nw = sum(1 for f in findings if f.severity == SEV_WARN)
    ni = sum(1 for f in findings if f.severity == SEV_INFO)

    finding_cards = "".join(f"""
        <article class="finding sev-{f.severity}">
          <div class="finding-head"><span class="chip chip-{f.severity}">{SEV_LABEL[f.severity]}</span>
            <span class="cat">{_esc(f.category)}</span><h3>{_esc(f.title)}</h3></div>
          <p class="detail">{_esc(f.detail)}</p>
          <div class="reco"><span class="reco-label">권장 조치</span>{_esc(f.recommendation)}</div>
        </article>""" for f in findings)

    # 회귀 분석
    if regr.has_baseline:
        delta = (regr.score_now or 0) - (regr.score_prev or 0)
        dcls = SEV_OK if delta >= 0 else SEV_CRIT
        sign = "+" if delta >= 0 else ""
        rows = "".join(
            f"<tr><td>{_esc(x['query_id'])}</td><td>{x['prev_ms']}</td><td>{x['now_ms']}</td>"
            f"<td style='color:var(--crit)'>+{x['delta_pct']}%</td>"
            f"<td>{_esc(x['query'][:90])}</td></tr>" for x in regr.regressed)
        reg_table = (f'<table><thead><tr><th>query_id</th><th>이전 mean(ms)</th>'
                     f'<th>현재 mean(ms)</th><th>증가</th><th>query</th></tr></thead>'
                     f'<tbody>{rows}</tbody></table>') if regr.regressed \
            else '<p class="muted">평균시간 회귀(≥50%) 쿼리 없음.</p>'
        regr_html = (f'<p class="kv">Baseline <b>{_esc(regr.baseline_at)}</b> 대비 &nbsp;·&nbsp; '
                     f'Health Score <b>{regr.score_prev} → {regr.score_now}</b> '
                     f'(<span style="color:var(--{dcls})">{sign}{delta}</span>)</p>{reg_table}')
    else:
        regr_html = f'<p class="muted">{_esc(regr.note)}</p>'

    # 상관
    if corr.spike_cpu is not None:
        body = (_table(corr.window_top) if corr.available
                else f'<p class="muted">{_esc(corr.note)}</p>')
        corr_html = (f'<p class="kv">CPU 피크 <b>{_esc(corr.spike_time)}</b> '
                     f'(<span style="color:var(--crit)">{corr.spike_cpu}%</span>) 시점 윈도우의 지배 쿼리'
                     f'</p><p class="note">{_esc(corr.note)}</p>{body}')
    else:
        corr_html = f'<p class="muted">{_esc(corr.note)}</p>'

    # EXPLAIN
    if explains:
        items = ""
        for e in explains:
            if e.ok:
                flags = ("".join(f'<span class="flag">{_esc(f)}</span>' for f in e.flags)
                         or '<span class="muted">특이 red flag 없음</span>')
                cost = f'<span class="cost">Total Cost {e.total_cost:,.0f}</span>' if e.total_cost else ""
                items += (f'<div class="exp"><div class="exp-h"><code>{_esc(e.query_id)}</code>{cost}</div>'
                          f'<div class="q">{_esc(e.query[:160])}</div><div class="flags">{flags}</div></div>')
            else:
                items += (f'<div class="exp"><div class="exp-h"><code>{_esc(e.query_id)}</code></div>'
                          f'<div class="q">{_esc(e.query[:160])}</div>'
                          f'<p class="err">EXPLAIN 불가: {_esc(e.error)}</p></div>')
        explain_html = items
    else:
        explain_html = ('<p class="muted">EXPLAIN 미수행 (PG16 미만이거나 비활성, '
                        '또는 대상 쿼리 없음). GENERIC_PLAN 은 PostgreSQL 16+ 에서 지원됩니다.</p>')

    # Query Store
    if qs.enabled:
        qs_html = (f'<div class="block"><h3>기간 상위 쿼리 (총 실행시간)</h3>{_table(qs.top)}</div>'
                   f'<div class="block"><h3>대기 통계 (pgms_wait_sampling)</h3>{_table(qs.waits)}</div>')
    else:
        qs_html = f'<p class="muted">Query Store 비활성: {_esc(qs.error or "—")}</p>'

    # Azure 메트릭 카드
    color_for = {"cpu_percent": "#0078D4", "memory_percent": "#8661c5", "iops": "#107c10",
                 "storage_percent": "#c8362f", "active_connections": "#336791"}
    label_for = {"cpu_percent": "CPU", "memory_percent": "메모리", "iops": "IOPS",
                 "storage_percent": "스토리지", "active_connections": "활성 연결"}
    metric_cards = ""
    for name, _u in AZURE_METRICS:
        m = metrics.get(name)
        col, label = color_for.get(name, "#0078D4"), label_for.get(name, name)
        if m is None:
            inner = '<p class="muted">미수집</p>'
        elif m.error:
            inner = f'<p class="err">{_esc(m.error)}</p>'
        else:
            unit = "%" if m.unit == "%" else ""
            inner = (f'<div class="metric-vals"><span>평균 <b>{m.avg_overall}{unit}</b></span>'
                     f'<span>최대 <b>{m.max_overall}{unit}</b></span></div>{_sparkline(m.avg, col)}')
        metric_cards += (f'<div class="metric-card"><div class="metric-name">'
                         f'<span class="dot" style="background:{col}"></span>{label}</div>{inner}</div>')

    # 엔진 상세
    sections = [("쿼리 성능", ["top_queries", "active_sessions"]),
                ("동시성 · 락", ["connections", "blocking"]),
                ("인덱스", ["unused_indexes", "seq_scans"]),
                ("유지보수 · 캐시", ["cache_hit", "dead_tuples", "checkpoints"]),
                ("구성 · 스토리지", ["parameters", "db_sizes"])]
    titles = {"top_queries": "총 실행시간 상위 쿼리", "active_sessions": "활성·장시간 세션",
              "connections": "연결 상태", "blocking": "블로킹 체인", "unused_indexes": "미사용 인덱스",
              "seq_scans": "Seq scan 과다 테이블", "cache_hit": "캐시 히트율",
              "dead_tuples": "Dead tuple/vacuum", "checkpoints": "체크포인트",
              "parameters": "서버 파라미터", "db_sizes": "데이터베이스 크기"}
    engine_sections = ""
    for sec_title, keys in sections:
        blocks = "".join(f'<div class="block"><h3>{titles.get(k,k)}</h3>{_table(engine.get(k))}</div>'
                         for k in keys)
        engine_sections += f'<section class="esec"><h2>{sec_title}</h2>{blocks}</section>'

    host_disp = _esc(cfg.host or ("DEMO 모드" if cfg.demo else "—"))
    span_disp = f"최근 {cfg.hours}시간" if (cfg.resource_id or cfg.demo) else "—"

    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PostgreSQL 진단 리포트 — {host_disp}</title>
<style>
 :root{{--ink:#15202b;--bg:#eef1f5;--card:#fff;--text:#1f2933;--muted:#64748b;--border:#e2e8f0;
  --azure:#0078D4;--pg:#336791;--crit:#c8362f;--warn:#b07b00;--info:#0a6cbd;--ok:#107c10;}}
 *{{box-sizing:border-box}}
 body{{margin:0;background:var(--bg);color:var(--text);line-height:1.5;
  font-family:"Segoe UI",system-ui,-apple-system,"Malgun Gothic",sans-serif}}
 code,.mono,table,.q,.flag,.cost{{font-family:"Cascadia Code","Consolas",ui-monospace,monospace}}
 .wrap{{max-width:1080px;margin:0 auto;padding:0 20px 64px}}
 header{{background:var(--ink);color:#e8eef4;padding:28px 0}}
 .hd{{max-width:1080px;margin:0 auto;padding:0 20px;display:flex;justify-content:space-between;
  align-items:center;gap:24px;flex-wrap:wrap}}
 header h1{{font-size:20px;margin:0 0 6px;font-weight:650;letter-spacing:-.2px}}
 .lvl{{display:inline-block;font-size:10.5px;letter-spacing:1px;background:rgba(0,120,212,.25);
  border:1px solid rgba(120,180,230,.4);color:#cfe6fb;border-radius:20px;padding:1px 9px;margin-left:8px}}
 header .meta{{font-size:12.5px;color:#9fb2c4}} header .meta b{{color:#cfe0ee;font-weight:600}}
 .score{{text-align:center;padding:10px 22px;border-radius:12px;background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.12)}}
 .score .num{{font-size:38px;font-weight:700;line-height:1}}
 .score .lab{{font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-top:4px}}
 .score.ok .num{{color:#5dd55d}} .score.warning .num{{color:#ffcf4d}} .score.critical .num{{color:#ff7a72}}
 .summary{{display:flex;gap:12px;margin:22px 0 8px;flex-wrap:wrap}}
 .stat{{flex:1;min-width:120px;background:var(--card);border:1px solid var(--border);
  border-radius:10px;padding:14px 16px}}
 .stat .n{{font-size:26px;font-weight:700}} .stat .l{{font-size:12px;color:var(--muted)}}
 .stat.crit .n{{color:var(--crit)}} .stat.warn .n{{color:var(--warn)}} .stat.info .n{{color:var(--info)}}
 h2{{font-size:15px;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);
  margin:34px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--border)}}
 .finding{{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--muted);
  border-radius:10px;padding:16px 18px;margin-bottom:12px}}
 .finding.sev-critical{{border-left-color:var(--crit)}} .finding.sev-warning{{border-left-color:var(--warn)}}
 .finding.sev-info{{border-left-color:var(--info)}} .finding.sev-ok{{border-left-color:var(--ok)}}
 .finding-head{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
 .finding-head h3{{font-size:15px;margin:0;flex-basis:100%}}
 .chip{{font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;color:#fff}}
 .chip-critical{{background:var(--crit)}} .chip-warning{{background:var(--warn)}}
 .chip-info{{background:var(--info)}} .chip-ok{{background:var(--ok)}}
 .cat{{font-size:11.5px;color:var(--muted);border:1px solid var(--border);padding:1px 8px;border-radius:20px}}
 .detail{{margin:10px 0;font-size:14px}}
 .reco{{background:#f1f6fb;border:1px solid #d8e7f4;border-radius:8px;padding:10px 12px;font-size:13.5px}}
 .reco-label{{display:inline-block;font-size:11px;font-weight:700;color:var(--azure);margin-right:8px;
  text-transform:uppercase;letter-spacing:.5px}}
 .panel{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px 18px}}
 .kv{{font-size:14px;margin:0 0 12px}} .kv b{{color:var(--pg)}}
 .exp{{border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:10px}}
 .exp-h{{display:flex;justify-content:space-between;align-items:center}}
 .exp-h code{{font-size:12px;color:var(--pg);font-weight:700}}
 .cost{{font-size:11.5px;color:var(--muted)}}
 .q{{font-size:11.5px;color:#334;margin:6px 0;overflow-wrap:anywhere}}
 .flags{{display:flex;gap:6px;flex-wrap:wrap}}
 .flag{{font-size:11px;background:#fff4e5;border:1px solid #f0d8b0;color:#8a5a00;
  padding:2px 8px;border-radius:6px}}
 .metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}}
 .metric-card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px}}
 .metric-name{{font-size:13px;font-weight:600;display:flex;align-items:center;gap:7px}}
 .dot{{width:9px;height:9px;border-radius:50%;display:inline-block}}
 .metric-vals{{display:flex;justify-content:space-between;font-size:12.5px;color:var(--muted);margin:8px 0 4px}}
 .metric-vals b{{color:var(--text);font-size:15px}} svg.spark{{width:100%;height:40px;display:block}}
 .block{{margin-bottom:20px}} .block h3{{font-size:14px;margin:0 0 8px;color:var(--pg)}}
 table{{width:100%;border-collapse:collapse;font-size:12px;background:var(--card);
  border:1px solid var(--border);border-radius:8px;overflow:hidden}}
 th{{background:#f3f6f9;text-align:left;padding:7px 9px;font-weight:600;color:#42526b;
  border-bottom:1px solid var(--border);white-space:nowrap}}
 td{{padding:6px 9px;border-bottom:1px solid #eef2f6;vertical-align:top;max-width:420px;overflow-wrap:anywhere}}
 tr:last-child td{{border-bottom:none}} tbody tr:hover{{background:#f8fbff}}
 .muted{{color:var(--muted);font-size:13px}} .err{{color:var(--crit);font-size:12.5px}}
 .note{{color:var(--muted);font-size:12px;margin:4px 0 8px}}
 footer{{color:var(--muted);font-size:12px;margin-top:40px;padding-top:16px;border-top:1px solid var(--border)}}
 @media (max-width:640px){{.hd{{flex-direction:column;align-items:flex-start}}}}
</style></head><body>
<header><div class="hd">
  <div><h1>Azure PostgreSQL Flexible Server 진단 리포트<span class="lvl">LEVEL 3</span></h1>
    <div class="meta">대상 <b>{host_disp}</b> · 버전 <b>{_esc(version_str or '—')}</b>
      · 메트릭 <b>{span_disp}</b> · 생성 {_esc(generated_at)}</div></div>
  <div class="score {score_cls}"><div class="num">{score}</div><div class="lab">{score_label}</div></div>
</div></header>
<div class="wrap">
  <div class="summary">
    <div class="stat crit"><div class="n">{nc}</div><div class="l">위험 (Critical)</div></div>
    <div class="stat warn"><div class="n">{nw}</div><div class="l">주의 (Warning)</div></div>
    <div class="stat info"><div class="n">{ni}</div><div class="l">정보 (Info)</div></div>
  </div>

  <h2>발견사항 및 권장 조치</h2>
  {finding_cards}

  <h2>회귀 분석 · Baseline 대비 (계층 3d)</h2>
  <div class="panel">{regr_html}</div>

  <h2>리소스-쿼리 상관 (계층 3c)</h2>
  <div class="panel">{corr_html}</div>

  <h2>실행계획 분석 · EXPLAIN GENERIC_PLAN (계층 3b)</h2>
  <div class="panel">{explain_html}</div>

  <h2>Query Store · 시간대별 쿼리 귀속 (계층 3a)</h2>
  {qs_html}

  <h2>리소스 추세 · Azure Monitor (계층 1)</h2>
  <div class="metrics">{metric_cards}</div>

  <h2>엔진 진단 상세 · PostgreSQL (계층 2)</h2>
  {engine_sections}

  <footer>
    <p>계층 1(Azure Monitor) + 계층 2(엔진 통계) + 계층 3(Query Store·EXPLAIN·상관·Baseline 회귀)
    결합. 읽기 전용이며 EXPLAIN 은 ANALYZE 없이 계획만 생성합니다(쿼리 미실행).</p>
    <p>임계치는 일반 OLTP 휴리스틱입니다. 상관 시각은 UTC 가정이며 서버 timezone 확인을 권장합니다.
    더 깊은 분석은 포털의 Query Performance Insight·Troubleshooting guides 와 병행하세요.</p>
  </footer>
</div></body></html>"""


# ──────────────────────────────────────────────────────────────────────────
# 데모 데이터
# ──────────────────────────────────────────────────────────────────────────
def demo_engine() -> dict[str, TableResult]:
    e = {}
    e["top_queries"] = TableResult(
        ["queryid", "calls", "total_ms", "mean_ms", "rows", "cache_hit_pct", "query"],
        [["-204417", 18422, 982155.4, 53.3, 18422, 88.2,
          "SELECT * FROM orders o JOIN order_items i ON i.order_id=o.id WHERE o.status=$1"],
         ["884213", 254119, 410233.1, 1.6, 254119, 99.8,
          "SELECT id,name,price FROM products WHERE sku=$1"],
         ["55120", 901, 88123.0, 97.8, 901, 71.0,
          "UPDATE inventory SET qty=qty-$1 WHERE product_id=$2"]])
    e["cache_hit"] = TableResult(
        ["datname", "cache_hit_pct", "xact_commit", "xact_rollback", "temp_files", "temp_bytes"],
        [["appdb", 96.5, 4821044, 1203, 142, "3812 MB"],
         ["postgres", 99.9, 88210, 4, 0, "0 bytes"]])
    e["active_sessions"] = TableResult(
        ["pid", "usename", "datname", "state", "wait_event_type", "wait_event", "dur_sec", "query"],
        [[20451, "appuser", "appdb", "active", "Lock", "relation", 184,
          "UPDATE inventory SET qty=qty-1 WHERE product_id=771"]])
    e["blocking"] = TableResult(
        ["blocked_pid", "blocked_user", "blocked_sec", "blocked_query", "blocking_pid", "blocking_query"],
        [[20451, "appuser", 184, "UPDATE inventory SET qty=qty-1 WHERE product_id=771",
          20310, "UPDATE inventory SET qty=qty+50 WHERE product_id=771 -- 미커밋"]])
    e["unused_indexes"] = TableResult(
        ["schemaname", "table_name", "index_name", "idx_scan", "index_size"],
        [["public", "orders", "idx_orders_legacy_ref", 0, "612 MB"]])
    e["dead_tuples"] = TableResult(
        ["schemaname", "table_name", "n_live_tup", "n_dead_tup", "dead_pct", "last_autovacuum", "last_autoanalyze"],
        [["public", "sessions", 120000, 88000, 42.3, "2026-06-08 22:14", "2026-06-08 22:14"]])
    e["seq_scans"] = TableResult(
        ["schemaname", "table_name", "seq_scan", "idx_scan", "seq_tup_read", "n_live_tup", "table_size"],
        [["public", "orders", 84120, 92011, 412000000000, 9800000, "7821 MB"]])
    e["connections"] = TableResult(
        ["total", "active", "idle", "idle_in_txn", "max_connections"], [[181, 22, 151, 8, 200]])
    e["parameters"] = TableResult(
        ["name", "setting", "unit", "source"],
        [["autovacuum", "on", None, "default"],
         ["effective_cache_size", "1572864", "8kB", "configuration file"],
         ["max_connections", "200", None, "configuration file"],
         ["shared_buffers", "524288", "8kB", "configuration file"],
         ["work_mem", "4096", "kB", "default"]])
    e["db_sizes"] = TableResult(["datname", "size"], [["appdb", "84 GB"], ["postgres", "12 MB"]])
    e["checkpoints"] = TableResult(
        ["checkpoints_timed", "checkpoints_req", "write_time_ms", "sync_time_ms", "buffers_written"],
        [[2104, 318, 1820041, 14820, 9120443]])
    return e


def demo_metrics() -> dict[str, MetricSeries]:
    import math
    base = dt.datetime(2026, 6, 9, 0, 0, tzinfo=dt.timezone.utc)
    raw = [base + dt.timedelta(hours=i) for i in range(24)]
    ts = [t.strftime("%m-%d %H:%M") for t in raw]

    def wave(b, a, n):
        return [round(b + a * math.sin(i / 3.0) + (i % 5) * n, 1) for i in range(24)]
    cpu = wave(48, 30, 1.2); cpu[14] = 92.4
    m = {}
    m["cpu_percent"] = MetricSeries("cpu_percent", "%", ts, raw, cpu, [v + 4 for v in cpu])
    mem = wave(68, 12, 0.6)
    m["memory_percent"] = MetricSeries("memory_percent", "%", ts, raw, mem, [v + 6 for v in mem])
    io = wave(2400, 900, 30)
    m["iops"] = MetricSeries("iops", "count", ts, raw, io, [v + 300 for v in io])
    st = [round(74 + i * 0.04, 1) for i in range(24)]
    m["storage_percent"] = MetricSeries("storage_percent", "%", ts, raw, st, st)
    cn = wave(150, 28, 1.0)
    m["active_connections"] = MetricSeries("active_connections", "count", ts, raw, cn, [v + 10 for v in cn])
    return m


def demo_query_store() -> QueryStoreData:
    d = QueryStoreData(enabled=True)
    d.top = TableResult(
        ["query_id", "calls", "total_ms", "mean_ms", "max_ms", "query"],
        [["-204417", 18422, 982155.4, 53.3, 2120.5,
          "SELECT * FROM orders o JOIN order_items i ON i.order_id=o.id WHERE o.status=$1"],
         ["55120", 901, 88123.0, 97.8, 880.1, "UPDATE inventory SET qty=qty-$1 WHERE product_id=$2"],
         ["884213", 254119, 410233.1, 1.6, 44.0, "SELECT id,name,price FROM products WHERE sku=$1"]])
    d.waits = TableResult(
        ["event_type", "event", "samples", "distinct_queries"],
        [["IO", "DataFileRead", 48210, 37], ["Lock", "relation", 12044, 5],
         ["CPU", "", 8800, 52], ["LWLock", "BufferMapping", 2310, 14]])
    return d


def demo_explains() -> list[ExplainResult]:
    return [
        ExplainResult("-204417",
            "SELECT * FROM orders o JOIN order_items i ON i.order_id=o.id WHERE o.status=$1",
            True, 184220.0, ["대형 Seq Scan: orders (≈9,800,000 rows) — 인덱스 후보",
                             "높은 추정 비용 (Total Cost 184,220)"]),
        ExplainResult("884213", "SELECT id,name,price FROM products WHERE sku=$1",
            True, 8.4, []),
        ExplainResult("55120", "UPDATE inventory SET qty=qty-$1 WHERE product_id=$2",
            True, 12.1, []),
    ]


def demo_correlation_window() -> TableResult:
    return TableResult(
        ["query_id", "calls", "total_ms", "mean_ms", "query"],
        [["-204417", 1840, 220411.0, 119.8,
          "SELECT * FROM orders o JOIN order_items i ON i.order_id=o.id WHERE o.status=$1"],
         ["55120", 88, 14220.0, 161.6, "UPDATE inventory SET qty=qty-$1 WHERE product_id=$2"]])


def demo_baseline() -> dict:
    return {"schema_version": 1, "host": "demo", "generated_at": "2026-06-02 22:00:00",
            "health_score": 68, "cache_hit_min": 98.9,
            "top_queries": {
                "-204417": {"mean_ms": 31.4, "calls": 17220, "total_ms": 540700.0},
                "884213": {"mean_ms": 1.5, "calls": 240110, "total_ms": 360120.0},
                "55120": {"mean_ms": 90.2, "calls": 880, "total_ms": 79376.0}}}


# ──────────────────────────────────────────────────────────────────────────
# 엔트리포인트
# ──────────────────────────────────────────────────────────────────────────
def parse_args(argv) -> Config:
    ba = argparse.BooleanOptionalAction
    p = argparse.ArgumentParser(
        description="Azure Database for PostgreSQL Flexible Server 진단 → HTML 리포트 (Level 3)")
    p.add_argument("--host"); p.add_argument("--port", type=int, default=5432)
    p.add_argument("--dbname", default="postgres"); p.add_argument("--user")
    p.add_argument("--password", help="미지정 시 PGPASSWORD 환경변수 사용")
    p.add_argument("--sslmode", default="require")
    p.add_argument("--aad", action="store_true", help="Entra ID(AAD) 토큰 인증")
    p.add_argument("--resource-id", help="Azure Monitor 대상 리소스 ID")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--granularity-min", type=int, default=5)
    p.add_argument("--query-store", action=ba, default=True, help="Query Store(azure_sys) 수집")
    p.add_argument("--explain", action=ba, default=True, help="EXPLAIN(GENERIC_PLAN) 수집 (PG16+)")
    p.add_argument("--explain-top", type=int, default=5)
    p.add_argument("--history", action=ba, default=True, help="Baseline 이력/회귀 비교")
    p.add_argument("--history-dir", default="./pg_diagnose_history")
    p.add_argument("--out", default="pg_report.html")
    p.add_argument("--demo", action="store_true")
    a = p.parse_args(argv)
    return Config(host=a.host, port=a.port, dbname=a.dbname, user=a.user, password=a.password,
                  sslmode=a.sslmode, use_aad=a.aad, resource_id=a.resource_id, hours=a.hours,
                  granularity_min=a.granularity_min, query_store=a.query_store, explain=a.explain,
                  explain_top=a.explain_top, history=a.history, history_dir=a.history_dir,
                  out=a.out, demo=a.demo)


def main(argv=None) -> int:
    cfg = parse_args(argv if argv is not None else sys.argv[1:])
    generated_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    auth = Auth(cfg)

    if cfg.demo:
        version_str = "16.4 (DEMO)"
        engine = demo_engine()
        metrics = demo_metrics()
        qs = demo_query_store()
        explains = demo_explains()
        corr = build_correlation(metrics, qs, None, demo_window=demo_correlation_window())
        qmap = collect_top_query_map(qs, engine)
        regr = compute_regressions(demo_baseline(), qmap, 0)  # score_now 보정은 아래
    else:
        if not cfg.host or not cfg.user:
            print("오류: 실제 진단에는 --host 와 --user 가 필요합니다 (또는 --demo).", file=sys.stderr)
            return 2
        ec = EngineCollector(cfg, auth)
        try:
            engine, explains = ec.collect()
            version_str = ec.version_str
        except Exception as e:  # noqa: BLE001
            print(f"엔진 수집 실패(연결 확인 필요): {e}", file=sys.stderr)
            return 1
        metrics = {}
        if cfg.resource_id:
            metrics = AzureMetricsCollector(cfg).collect()
        else:
            print("참고: --resource-id 미지정 → Azure Monitor 메트릭 생략.", file=sys.stderr)
        qs = QueryStoreData()
        qs_collector = None
        if cfg.query_store:
            qs_collector = QueryStoreCollector(cfg, auth)
            qs = qs_collector.collect()
        corr = build_correlation(metrics, qs, qs_collector)
        qmap = collect_top_query_map(qs, engine)
        regr = compute_regressions(load_baseline(cfg), qmap, 0)

    # 분석 → 점수 → (회귀 점수 보정) → 렌더
    findings = Analyzer(engine, metrics, qs, explains, regr).run()
    score = health_score(findings)
    regr.score_now = score

    cache_min = None
    ch = engine.get("cache_hit")
    if ch and not ch.error and ch.rows:
        ci = ch.columns.index("cache_hit_pct")
        vals = [float(r[ci]) for r in ch.rows if r[ci] is not None]
        cache_min = min(vals) if vals else None
    save_snapshot(cfg, version_str, score, metrics, engine, qmap, cache_min)

    out_html = render_html(cfg, version_str, engine, metrics, qs, explains, corr, regr,
                           findings, generated_at)
    with open(cfg.out, "w", encoding="utf-8") as fh:
        fh.write(out_html)
    print(f"리포트 생성 완료: {cfg.out}  (Health Score: {score}, "
          f"위험 {sum(1 for f in findings if f.severity==SEV_CRIT)}건, "
          f"회귀 {len(regr.regressed)}건)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
