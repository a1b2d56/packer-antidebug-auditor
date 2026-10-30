import aiosqlite
import json
from typing import Optional, Dict, Any, List

from server.config import DB_PATH

async def init_db():
    async with aiosqlite.connect(DB_PATH, timeout=10) as db:
        # WAL lets the SSE/GET readers proceed while a finished job is being written.
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                verdict TEXT,
                risk_score INTEGER,
                ml_label TEXT,
                ml_probability REAL,
                vt_detection_ratio TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                result_json TEXT NOT NULL
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON scans(sha256)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_verdict ON scans(verdict)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_created ON scans(created_at DESC)")
        
        # FTS5 for full-text search
        await db.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS scans_fts USING fts5(
                file_name, sha256, result_json,
                content='scans', content_rowid='rowid'
            )
        """)
        
        await db.commit()

async def get_scan_by_id(job_id: str) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH, timeout=10) as db:
        async with db.execute("SELECT result_json FROM scans WHERE id = ?", (job_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return json.loads(row[0])
    return None

async def get_scan_by_hash(sha256: str) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH, timeout=10) as db:
        async with db.execute("SELECT result_json FROM scans WHERE sha256 = ? ORDER BY created_at DESC LIMIT 1", (sha256,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return json.loads(row[0])
    return None

async def save_scan(job_id: str, sha256: str, file_name: str, file_type: str, file_size: int, result: Dict[str, Any]):
    verdict_str = None
    score = 0
    ml_label = None
    ml_prob = None
    vt_ratio = None
    
    if result.get("verdict"):
        verdict_str = result["verdict"].get("verdict")
        score = result["verdict"].get("score", 0)
        
    if result.get("ml_prediction"):
        ml_label = result["ml_prediction"].get("label")
        ml_prob = result["ml_prediction"].get("probability")
        
    result_json = json.dumps(result)
    
    async with aiosqlite.connect(DB_PATH, timeout=10) as db:
        await db.execute("""
            INSERT INTO scans (id, sha256, file_name, file_type, file_size, verdict, risk_score, ml_label, ml_probability, vt_detection_ratio, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (job_id, sha256, file_name, file_type, file_size, verdict_str, score, ml_label, ml_prob, vt_ratio, result_json))
        
        # Insert into FTS
        await db.execute("""
            INSERT INTO scans_fts (rowid, file_name, sha256, result_json)
            VALUES (last_insert_rowid(), ?, ?, ?)
        """, (file_name, sha256, result_json))
        
        await db.commit()
