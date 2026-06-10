# 🚀 pg_diagnose (Level 3)

**Azure Database for PostgreSQL Flexible Server 진단 도구**

PostgreSQL 성능 이슈를  
👉 *"메트릭 → 쿼리 → 실행계획"*까지 연결해 분석하고  
👉 **Portable HTML 리포트**로 출력하는 도구입니다.

---

## ✨ Key Features

- ✅ Level 1~3 통합 진단
- ✅ 단일 HTML 리포트 (Export 가능 / Offline 지원)
- ✅ CPU Spike ↔ Query 상관 분석
- ✅ Query Regression (Baseline 비교)
- ✅ EXPLAIN 기반 실행계획 분석 (Non-intrusive)

---

## 🧱 Multi-Level Diagnostics

| Level | Description |
|------|------------|
| Level 1 | Azure Monitor (CPU / Memory / IOPS / Connections) |
| Level 2 | PostgreSQL 내부 상태 (쿼리, 세션, 블로킹, 캐시 등) |
| Level 3 | 상관 분석 + 근본 원인 단서 |

### Level 3 Details

- **3a Query Store** → 15분 단위 쿼리 + wait stats  
- **3b EXPLAIN** → 실행 없이 plan 분석 (GENERIC_PLAN, PG16+)  
- **3c Correlation** → CPU spike 시점 ↔ 지배 쿼리  
- **3d Regression** → 쿼리 latency 변화 탐지  

---

## 🔐 Safety

- Read-only (데이터/설정 변경 없음)
- EXPLAIN without `ANALYZE`
- DML 포함 실행 없음 (safe)
- Partial failure tolerant (일부 실패 시에도 리포트 생성)

---

## ⚙️ Prerequisites

### Required

1. `pg_stat_statements` (계층 2 쿼리 성능)
   * `shared_preload_libraries` 에 추가 → 재시작 → `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;`
2. Query Store (계층 3a)
   * 서버 파라미터 `pg_qs.query_capture_mode` = `top` 또는 `all`
   * 대기 통계: `pgms_wait_sampling.query_capture_mode` = `all`
   * 데이터는 `azure_sys` DB 의 `query_store` 스키마에 저장(public 롤 읽기 가능, 15분 집계)
   * ⚠️ Burstable 티어에서는 활성화 금지(성능 영향). 비활성 시 해당 섹션만 생략됩니다.
3. Azure Monitor (계층 1)
   * 실행 주체에 대상 리소스 Monitoring Reader 역할, 로컬은 `az login` (`DefaultAzureCredential`)
4. DB 접근
   * 비밀번호: `--password` 또는 `PGPASSWORD`
   * Entra ID 토큰: `--aad`
   * Private Endpoint/VNet 환경이면 도구를 해당 네트워크 내에서 실행

## ⚙️ Installation & Execution
- Install
  * pip install -r requirements.txt
  * python pg_diagnose.py --demo --out sample_report.html # --demo 옵션 사용시 설치 없이 동작
    
- Full Diagnosis (Level 1~3) 전체 진단
  export PGPASSWORD='***'
  python pg_diagnose.py \
  --host <name>.postgres.database.azure.com --dbname appdb --user pgadmin \
  --resource-id "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.DBforPostgreSQL/flexibleServers/<name>" \
  --hours 24 --out report.html
  
- Entra ID 인증 + 일부 계층 끄기
  python pg_diagnose.py --aad --no-explain \
  --host <name>.postgres.database.azure.com --dbname appdb --user "me@contoso.com" \
  --resource-id "/subscriptions/.../flexibleServers/<name>" --out report.html
  
- 🧰 CLI Options
  * '--host / --port / --dbname / --user' (설명 - DB connectionm , 기본값 - 5432 /postgres)
  * `--password` / `--aad` (설명 - 비밀번호 또는 Entra ID 토큰, 기본값 - 'PGPASSWRD')
  * `--resource-id` (설명 - Azure Monitor 대상, 기본값 - 미지정 시 메트릭 생략)
  * `--hours` / `--granularity-min` (설명 - 메트릭·Query Store 기간/간격, 기본값 - 24h / 5분)
  * `--query-store` / `--no-query-store` (설명 - 계층 3a 수집, 기본값 - on)
  * --explain` / `--no-explain` / `--explain-top N`(설명 - 계층 3b 수집/개수, 기본값 - on / 5)
  * `--history` / `--no-history` / `--history-dir`(설명 - 계층 3d baseline, 기본값 - on / `./pg_diagnose_history`)
  * `--out`(설명 - 출력 HTML, 기본값 - `pg_report.html`)
  * `--demo`(설명 - 샘플 데이터 렌더링, 기본값 - off)

## 🧠 Level 3 Deep Dive
- 상관(3c) 시각은 UTC 가정입니다. Azure Monitor 타임스탬프는 UTC(aware)이고 Query Store `start_time`/`end_time` 은 서버 로컬 `timestamp` 라, 서버 timezone 이 UTC 가 아니면 윈도우 정합을 확인하세요. 리포트에도 동일 caveat 가 표기됩니다.
  
- 회귀(3d) 는 실행 시마다 `--history-dir` 에 스냅샷(JSON)을 적재하고, 같은 host 의 직전 스냅샷과 비교합니다. 쿼리 평균시간이 50% 이상 & 절대 5ms 이상 증가하면 회귀로 표시합니다. 첫 실행에는 baseline 이 없어 비교를 생략합니다. `query_id` 는 재시작에도 안정적인 Query Store 값을 우선 사용하고, 없으면 `pg_stat_statements` 의 `queryid` 를 씁니다.
  
- EXPLAIN(3b) 은 상위 N개 쿼리에 대해 `EXPLAIN (GENERIC_PLAN, FORMAT JSON)` 을 수행하고 플랜을 파싱해 대형 Seq Scan(인덱스 후보), 높은 Total Cost 등을 red flag 로 노출합니다. 잘린 쿼리 텍스트나 EXPLAIN 미지원 문장은 건너뜁니다.

## ⚠️ Limitations
- Index 자동 생성 (DDL) 미지원 (후보까지만)
- bloat = dead tuple 기반 추정 (정밀 아님)
- anomaly detection 제한적 (baseline 기반만)
- 자동 remediation intentionally excluded

## 🔮 Future Enhancements (Level 4)
- EXPLAIN + ANALYZE 기반 계획 비교
- Index recommendation engine
- Replication lag (pg_stat_replication)
- PgBouncer / connection pooling metrics
- Scheduled execution (Azure Functions / Container Apps)
- Blob storage + Power BI trend analysis
