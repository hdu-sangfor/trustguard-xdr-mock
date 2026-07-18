# -*- coding: utf-8 -*-
"""SQLite 状态仓库。

官方样例在首次启动时导入为基础数据；场景数据带 scenario_id，可单独重置。
API 层只面向本仓库，不直接依赖样例文件，因此处置状态能够跨请求保留。
"""
from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

from ..config import state_db_path
from ..generators.loader import load_samples


SAMPLE_KINDS = {
    "alerts": "安全告警",
    "incidents": "安全事件",
    "dns": "DNS日志",
    "endpoint_security": "端点安全日志",
    "endpoint_behavior": "终端行为日志",
    "network_security": "网络安全日志",
}

BASE_ASSETS = [
    {
        "assetId": "A12345678",
        "hostAssetId": "A12345678",
        "hostIp": "192.168.75.35",
        "ip": "192.168.75.35",
        "name": "demo-host",
        "hostName": "demo-host",
        "branchId": 1,
        "branchName": "研发部",
        "tags": ["demo"],
    },
    {
        "assetId": "A12345679",
        "hostAssetId": "A12345679",
        "hostIp": "10.0.0.30",
        "ip": "10.0.0.30",
        "name": "demo-host2",
        "hostName": "demo-host2",
        "branchId": 2,
        "branchName": "运维部",
        "tags": ["demo"],
    },
]


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _plain_record(record: dict) -> dict:
    data = record.get("data")
    return copy.deepcopy(data if isinstance(data, dict) else record)


def _first(value: Any) -> str:
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


def _record_uuid(payload: dict) -> str:
    for key in ("uuId", "uuid", "logId", "id"):
        if payload.get(key) not in (None, ""):
            return str(payload[key])
    digest = hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()[:24]
    return f"generated-{digest}"


def _record_ts(payload: dict) -> int:
    for key in (
        "recordTimestamp",
        "occurTimestamp",
        "startTimestamp",
        "uploadTimestamp",
        "sendTime",
    ):
        value = payload.get(key)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return 0


def _as_set(value: Any) -> set[str]:
    if value in (None, "", []):
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(item) for item in value}
    return {str(value)}


def _field_values(payload: dict, *keys: str) -> set[str]:
    values: set[str] = set()
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            values.update(str(item) for item in value)
        elif value not in (None, ""):
            values.add(str(value))
    return values


class XdrRepository:
    """小规模联调数据的线程安全 SQLite Repository。"""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _initialize(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS records (
                    kind TEXT NOT NULL,
                    record_uuid TEXT NOT NULL,
                    record_ts INTEGER NOT NULL DEFAULT 0,
                    scenario_id TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'sample',
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (kind, record_uuid)
                );
                CREATE INDEX IF NOT EXISTS idx_records_kind_ts
                    ON records(kind, record_ts DESC);
                CREATE INDEX IF NOT EXISTS idx_records_scenario
                    ON records(scenario_id);

                CREATE TABLE IF NOT EXISTS assets (
                    asset_id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS whitelists (
                    white_id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS block_rules (
                    rule_id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL DEFAULT '',
                    side TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS virus_tasks (
                    task_id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scenarios (
                    scenario_id TEXT PRIMARY KEY,
                    seeded_at REAL NOT NULL,
                    ground_truth_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            seeded = conn.execute(
                "SELECT value FROM meta WHERE key='base_seed_version'"
            ).fetchone()
            if seeded is None:
                self._seed_base(conn)
                conn.execute(
                    "INSERT INTO meta(key, value) VALUES('base_seed_version', '1')"
                )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('clock_offset', '0')"
            )

    def _seed_base(self, conn: sqlite3.Connection) -> None:
        for kind, spec_key in SAMPLE_KINDS.items():
            for raw in load_samples(spec_key):
                self._put_record(conn, kind, _plain_record(raw), "", "official_sample")
        for asset in BASE_ASSETS:
            self._put_asset(conn, asset, "")

    @staticmethod
    def _put_record(
        conn: sqlite3.Connection,
        kind: str,
        payload: dict,
        scenario_id: str,
        source: str,
    ) -> None:
        conn.execute(
            """INSERT OR REPLACE INTO records
               (kind, record_uuid, record_ts, scenario_id, source, payload_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                kind,
                _record_uuid(payload),
                _record_ts(payload),
                scenario_id,
                source,
                _json(payload),
            ),
        )

    @staticmethod
    def _put_asset(conn: sqlite3.Connection, payload: dict, scenario_id: str) -> None:
        asset_id = str(payload.get("assetId") or payload.get("hostAssetId") or "")
        if not asset_id:
            raise ValueError("assetId is required")
        conn.execute(
            "INSERT OR REPLACE INTO assets(asset_id, scenario_id, payload_json) VALUES(?,?,?)",
            (asset_id, scenario_id, _json(payload)),
        )

    # ---- 通用记录查询与处置 -------------------------------------------------
    def list_records(self, kinds: str | Iterable[str], filters: dict) -> tuple[list[dict], int]:
        kinds = [kinds] if isinstance(kinds, str) else list(kinds)
        placeholders = ",".join("?" for _ in kinds)
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"SELECT payload_json, record_ts FROM records WHERE kind IN ({placeholders})",
                kinds,
            ).fetchall()
        records = [(json.loads(row["payload_json"]), int(row["record_ts"])) for row in rows]
        records = [item for item in records if self._matches_record(item[0], item[1], filters)]
        reverse = str(filters.get("sortOrder", filters.get("sortType", "desc"))).lower() not in {
            "asc",
            "1",
        }
        records.sort(key=lambda item: item[1], reverse=reverse)
        total = len(records)
        page, page_size = self.pagination(filters)
        start = (page - 1) * page_size
        return [payload for payload, _ in records[start : start + page_size]], total

    @staticmethod
    def pagination(filters: dict, default_size: int = 20) -> tuple[int, int]:
        page = max(1, int(filters.get("page", 1)))
        page_size = min(500, max(1, int(filters.get("pageSize", default_size))))
        return page, page_size

    @staticmethod
    def _matches_record(payload: dict, ts: int, filters: dict) -> bool:
        start = filters.get("startTimestamp")
        end = filters.get("endTimestamp")
        if start is not None and ts and ts < int(start):
            return False
        if end is not None and ts and ts > int(end):
            return False

        wanted_uuids = _as_set(filters.get("uuIds"))
        if wanted_uuids and _record_uuid(payload) not in wanted_uuids:
            return False

        mappings = [
            (("severities", "severity"), ("severity", "riskLevel")),
            (("productTypes", "productType"), ("productType", "originProductType")),
            (("srcIps", "srcIp"), ("srcIp",)),
            (("dstIps", "dstIp"), ("dstIp",)),
            (("hostIps", "hostIp"), ("hostIp",)),
            (
                ("hostAssetIds", "platformHostAssetIds", "assetIds", "assetId"),
                ("assetId", "hostAssetId", "srcAssetId", "dstAssetId"),
            ),
            (("threatTypes", "threatType"), ("threatType",)),
            (("threatSubTypes", "threatSubType"), ("threatSubType",)),
            (("attackStates", "attackState"), ("attackState", "attackResult")),
        ]
        for request_keys, payload_keys in mappings:
            wanted: set[str] = set()
            for key in request_keys:
                wanted.update(_as_set(filters.get(key)))
            if wanted and not wanted.intersection(_field_values(payload, *payload_keys)):
                return False

        status = filters.get("alertDealStatus", filters.get("dealStatus"))
        if status not in (None, "", []):
            if not _as_set(status).intersection(_field_values(payload, "dealStatus")):
                return False

        fuzzy = str(
            filters.get("fuzzyParam")
            or filters.get("filterParam")
            or filters.get("keyword")
            or ""
        ).strip().lower()
        if fuzzy and fuzzy not in _json(payload).lower():
            return False
        return True

    def get_record(self, kind: str, record_uuid: str) -> dict | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM records WHERE kind=? AND record_uuid=?",
                (kind, record_uuid),
            ).fetchone()
        return json.loads(row["payload_json"]) if row else None

    def update_deal_status(
        self, kind: str, uuids: list[str], deal_status: Any, comment: str = ""
    ) -> tuple[int, int]:
        succeeded = 0
        with self._lock, self._connect() as conn:
            for record_uuid in uuids:
                row = conn.execute(
                    "SELECT payload_json FROM records WHERE kind=? AND record_uuid=?",
                    (kind, str(record_uuid)),
                ).fetchone()
                if not row:
                    continue
                payload = json.loads(row["payload_json"])
                payload["dealStatus"] = deal_status
                payload["dealComment"] = comment
                payload["dealTimestamp"] = int(self.now())
                conn.execute(
                    "UPDATE records SET payload_json=? WHERE kind=? AND record_uuid=?",
                    (_json(payload), kind, str(record_uuid)),
                )
                succeeded += 1
        return len(uuids), succeeded

    # ---- 资产 ---------------------------------------------------------------
    def list_assets(self, filters: dict) -> tuple[list[dict], int]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT payload_json FROM assets ORDER BY asset_id").fetchall()
        assets = [json.loads(row["payload_json"]) for row in rows]
        ids = set()
        for key in ("assetIds", "hostAssetIds", "assetId"):
            ids.update(_as_set(filters.get(key)))
        if ids:
            assets = [a for a in assets if str(a.get("assetId")) in ids]
        ip = str(filters.get("ip") or filters.get("hostIp") or "").strip().lower()
        if ip:
            assets = [a for a in assets if ip in str(a.get("hostIp", a.get("ip", ""))).lower()]
        name = str(filters.get("hostName") or filters.get("name") or "").strip().lower()
        if name:
            assets = [a for a in assets if name in str(a.get("hostName", a.get("name", ""))).lower()]
        branch_ids = _as_set(filters.get("branchIds", filters.get("branchId")))
        if branch_ids:
            assets = [a for a in assets if str(a.get("branchId")) in branch_ids]
        total = len(assets)
        page, page_size = self.pagination(filters, default_size=10)
        start = (page - 1) * page_size
        return assets[start : start + page_size], total

    def upsert_assets(self, assets: list[dict], scenario_id: str = "") -> int:
        with self._lock, self._connect() as conn:
            for asset in assets:
                self._put_asset(conn, asset, scenario_id)
        return len(assets)

    def delete_assets(self, asset_ids: list[str]) -> int:
        with self._lock, self._connect() as conn:
            cursor = conn.executemany(
                "DELETE FROM assets WHERE asset_id=?", [(str(item),) for item in asset_ids]
            )
        return cursor.rowcount

    # ---- 白名单 -------------------------------------------------------------
    def list_whitelists(self, filters: dict) -> tuple[list[dict], int]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT payload_json FROM whitelists ORDER BY white_id").fetchall()
        items = [json.loads(row["payload_json"]) for row in rows]
        keyword = str(filters.get("keyword") or "").strip().lower()
        if keyword:
            items = [item for item in items if keyword in _json(item).lower()]
        statuses = _as_set(filters.get("status"))
        if statuses:
            items = [item for item in items if str(item.get("status")) in statuses]
        total = len(items)
        page, page_size = self.pagination(filters)
        start = (page - 1) * page_size
        return items[start : start + page_size], total

    def save_whitelist(
        self, payload: dict, white_id: str | None = None, scenario_id: str = ""
    ) -> dict:
        item = copy.deepcopy(payload)
        white_id = str(white_id or item.get("whiteId") or f"WL-{uuid.uuid4().hex[:12]}")
        now = int(self.now())
        item.update({"whiteId": white_id, "updateTime": now})
        item.setdefault("createTime", now)
        item.setdefault("status", 1)
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO whitelists(white_id, scenario_id, payload_json) VALUES(?,?,?)",
                (white_id, scenario_id, _json(item)),
            )
        return item

    def set_whitelist_status(self, white_id: str, status: Any) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT scenario_id,payload_json FROM whitelists WHERE white_id=?", (white_id,)
            ).fetchone()
            if not row:
                return False
            item = json.loads(row["payload_json"])
            item["status"] = status
            item["updateTime"] = int(self.now())
            conn.execute(
                "UPDATE whitelists SET payload_json=? WHERE white_id=?",
                (_json(item), white_id),
            )
        return True

    def delete_whitelists(self, white_ids: list[str]) -> int:
        with self._lock, self._connect() as conn:
            cursor = conn.executemany(
                "DELETE FROM whitelists WHERE white_id=?",
                [(str(item),) for item in white_ids],
            )
        return cursor.rowcount

    def match_whitelists(self, context: dict) -> list[dict]:
        items, _ = self.list_whitelists({"page": 1, "pageSize": 500})
        blob = _json(context).lower()
        matched = []
        for item in items:
            if str(item.get("status", 1)) not in {"1", "true", "enabled", "ENABLE"}:
                continue
            rules = item.get("ruleList") or []
            host_ip = str(item.get("hostIp") or "").lower()
            terms = [host_ip] if host_ip else []
            for rule in rules:
                if isinstance(rule, dict):
                    terms.extend(str(v).lower() for v in rule.values() if v not in (None, ""))
                elif rule not in (None, ""):
                    terms.append(str(rule).lower())
            if any(term and term in blob for term in terms):
                matched.append(item)
        return matched

    # ---- 响应任务 -----------------------------------------------------------
    def create_block_rule(self, payload: dict, side: str, scenario_id: str = "") -> dict:
        rule_id = str(payload.get("ruleId") or f"BR-{uuid.uuid4().hex[:12]}")
        item = copy.deepcopy(payload)
        item.update({"ruleId": rule_id, "side": side, "status": "BLOCKED"})
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO block_rules
                   (rule_id,scenario_id,side,status,created_at,payload_json) VALUES(?,?,?,?,?,?)""",
                (rule_id, scenario_id, side, "BLOCKED", self.now(), _json(item)),
            )
        return item

    def set_block_status(self, rule_id: str, status: str) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM block_rules WHERE rule_id=?", (rule_id,)
            ).fetchone()
            if not row:
                return False
            item = json.loads(row["payload_json"])
            item["status"] = status
            conn.execute(
                "UPDATE block_rules SET status=?,payload_json=? WHERE rule_id=?",
                (status, _json(item), rule_id),
            )
        return True

    def list_block_rules(self, filters: dict) -> tuple[list[dict], int]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM block_rules ORDER BY created_at DESC"
            ).fetchall()
        items = [json.loads(row["payload_json"]) for row in rows]
        total = len(items)
        page, page_size = self.pagination(filters)
        start = (page - 1) * page_size
        return items[start : start + page_size], total

    def create_virus_task(self, payload: dict, scenario_id: str = "") -> dict:
        task_id = f"VT-{uuid.uuid4().hex[:12]}"
        item = copy.deepcopy(payload)
        item.update({"taskId": task_id, "status": "CREATED"})
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO virus_tasks(task_id,scenario_id,created_at,payload_json) VALUES(?,?,?,?)",
                (task_id, scenario_id, self.now(), _json(item)),
            )
        return item

    def get_virus_task(self, task_id: str) -> dict | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT created_at,payload_json FROM virus_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
        if not row:
            return None
        item = json.loads(row["payload_json"])
        elapsed = self.now() - float(row["created_at"])
        item["status"] = "SUCCESS" if elapsed >= 3 else "RUNNING" if elapsed >= 1 else "CREATED"
        item.setdefault("item", item.get("devices", []))
        return item

    # ---- 场景与虚拟时钟 -----------------------------------------------------
    def seed_scenario(self, scenario: dict) -> dict:
        scenario_id = str(scenario["scenarioId"])
        self.reset_scenario(scenario_id)
        with self._lock, self._connect() as conn:
            for entry in scenario.get("records", []):
                self._put_record(
                    conn, entry["kind"], entry["payload"], scenario_id, "mock_scenario"
                )
            for asset in scenario.get("assets", []):
                self._put_asset(conn, asset, scenario_id)
            for item in scenario.get("whitelists", []):
                white_id = str(item["whiteId"])
                conn.execute(
                    "INSERT OR REPLACE INTO whitelists(white_id,scenario_id,payload_json) VALUES(?,?,?)",
                    (white_id, scenario_id, _json(item)),
                )
            conn.execute(
                "INSERT OR REPLACE INTO scenarios(scenario_id,seeded_at,ground_truth_json) VALUES(?,?,?)",
                (scenario_id, self.now(), _json(scenario.get("groundTruth", {}))),
            )
        return {
            "scenarioId": scenario_id,
            "records": len(scenario.get("records", [])),
            "assets": len(scenario.get("assets", [])),
            "whitelists": len(scenario.get("whitelists", [])),
        }

    def reset_scenario(self, scenario_id: str) -> None:
        with self._lock, self._connect() as conn:
            for table in ("records", "assets", "whitelists", "block_rules", "virus_tasks"):
                conn.execute(f"DELETE FROM {table} WHERE scenario_id=?", (scenario_id,))
            conn.execute("DELETE FROM scenarios WHERE scenario_id=?", (scenario_id,))

    def reset_scenarios(self) -> int:
        with self._lock, self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) AS c FROM scenarios").fetchone()["c"]
            for table in ("records", "assets", "whitelists", "block_rules", "virus_tasks"):
                conn.execute("DELETE FROM " + table + " WHERE scenario_id<>''")
            conn.execute("DELETE FROM scenarios")
            conn.execute("UPDATE meta SET value='0' WHERE key='clock_offset'")
        return int(count)

    def ground_truth(self, scenario_id: str) -> dict | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT ground_truth_json FROM scenarios WHERE scenario_id=?", (scenario_id,)
            ).fetchone()
        return json.loads(row["ground_truth_json"]) if row else None

    def timeline(self, scenario_id: str) -> list[dict]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """SELECT kind,record_uuid,record_ts,payload_json FROM records
                   WHERE scenario_id=? ORDER BY record_ts,kind""",
                (scenario_id,),
            ).fetchall()
        return [
            {
                "kind": row["kind"],
                "uuId": row["record_uuid"],
                "timestamp": row["record_ts"],
                "payload": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def now(self) -> float:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key='clock_offset'").fetchone()
        return time.time() + float(row["value"] if row else 0)

    def advance_clock(self, seconds: int) -> float:
        if seconds < 0:
            raise ValueError("seconds must be >= 0")
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key='clock_offset'").fetchone()
            offset = float(row["value"] if row else 0) + seconds
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES('clock_offset',?)",
                (str(offset),),
            )
        return time.time() + offset


_REPOSITORY: XdrRepository | None = None
_REPOSITORY_LOCK = threading.Lock()


def get_repository() -> XdrRepository:
    global _REPOSITORY
    if _REPOSITORY is None:
        with _REPOSITORY_LOCK:
            if _REPOSITORY is None:
                _REPOSITORY = XdrRepository(state_db_path())
    return _REPOSITORY
