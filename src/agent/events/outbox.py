"""Private bounded journal; permanently rejected evidence remains quarantined."""
import json
import os
import sqlite3
import uuid
from pathlib import Path
from contextlib import contextmanager


class DeliveryPending(RuntimeError):
    pass


class DurableOutbox:
    MAX_EVENT_BYTES = 256 * 1024
    MAX_STORAGE_BYTES = 256 * 1024 * 1024

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError('Outbox must not be a symbolic link')
        os.chmod(path.parent, 0o700)
        self.path = path
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS pending (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, payload TEXT NOT NULL, batch_id TEXT)')
            db.execute('CREATE INDEX IF NOT EXISTS ix_pending_batch ON pending(batch_id)')
            db.execute('CREATE TABLE IF NOT EXISTS quarantined (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, batch_id TEXT NOT NULL, reason TEXT NOT NULL, quarantined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)')
            db.execute('CREATE TABLE IF NOT EXISTS usage (id INTEGER PRIMARY KEY, bytes INTEGER NOT NULL)')
            db.execute('INSERT OR IGNORE INTO usage VALUES(1, (SELECT coalesce(sum(length(payload)),0) FROM pending))')
            db.execute('CREATE TRIGGER IF NOT EXISTS usage_insert AFTER INSERT ON pending BEGIN UPDATE usage SET bytes=bytes+length(new.payload) WHERE id=1; END')
            db.execute('CREATE TRIGGER IF NOT EXISTS usage_delete AFTER DELETE ON pending BEGIN UPDATE usage SET bytes=bytes-length(old.payload) WHERE id=1; END')
            db.execute('CREATE TRIGGER IF NOT EXISTS quarantine_usage_insert AFTER INSERT ON quarantined BEGIN UPDATE usage SET bytes=bytes+length(new.payload) WHERE id=1; END')
        os.chmod(path, 0o600)

    @contextmanager
    def connect(self):
        # SQLite's rollback journal gives atomic durable commits; one connection per call.
        db = sqlite3.connect(self.path, timeout=10)
        db.execute('PRAGMA synchronous=FULL')
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def append(self, event):
        payload = json.dumps(event, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        size = len(payload.encode())
        if size > self.MAX_EVENT_BYTES:
            raise ValueError('Event exceeds the evidence size limit')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT payload FROM pending WHERE event_id=? UNION ALL SELECT payload FROM quarantined WHERE event_id=?', (event['event_id'], event['event_id'])).fetchone()
            if existing:
                if existing[0] != payload:
                    raise ValueError('An event ID cannot be reused with different evidence')
                return False
            used = db.execute('SELECT bytes FROM usage WHERE id=1').fetchone()[0]
            if used + size > self.MAX_STORAGE_BYTES:
                raise DeliveryPending('Local delivery storage is full; scan must stop')
            db.execute('INSERT INTO pending(event_id,payload) VALUES(?,?)', (event['event_id'], payload))
            return True

    def next_batch(self):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            head = db.execute('SELECT batch_id FROM pending ORDER BY seq LIMIT 1').fetchone()
            if not head:
                return None
            if head[0]:
                rows = db.execute('SELECT seq,payload FROM pending WHERE batch_id=? ORDER BY seq', (head[0],)).fetchall()
                return head[0], [json.loads(row[1]) for row in rows]
            rows = db.execute('SELECT seq,payload FROM pending WHERE batch_id IS NULL ORDER BY seq LIMIT 200').fetchall()
            chosen, size = [], 1024
            for row in rows:
                if chosen and size + len(row[1]) + 20 > 1024 * 1024:
                    break
                chosen.append(row)
                size += len(row[1]) + 20
            batch_id = str(uuid.uuid4())
            db.executemany('UPDATE pending SET batch_id=? WHERE seq=?', [(batch_id, row[0]) for row in chosen])
            return batch_id, [json.loads(row[1]) for row in chosen]

    def acknowledge(self, batch_id):
        with self.connect() as db:
            db.execute('DELETE FROM pending WHERE batch_id=?', (batch_id,))

    def quarantine_unassigned(self, batch_id, rejected_scan_ids):
        """Atomically retain server-rejected records and re-batch eligible ones."""
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            rows = db.execute('SELECT seq,event_id,payload FROM pending WHERE batch_id=?', (batch_id,)).fetchall()
            moved = 0
            for seq, event_id, payload in rows:
                if json.loads(payload).get('scan_id') in rejected_scan_ids:
                    db.execute('INSERT INTO quarantined(event_id,payload,batch_id,reason) VALUES(?,?,?,?)',
                               (event_id, payload, batch_id, 'scan_not_assigned'))
                    db.execute('DELETE FROM pending WHERE seq=?', (seq,))
                    moved += 1
            if not moved:
                raise DeliveryPending('Rejection does not match queued evidence')
            # No member of this batch was accepted; a changed payload needs a new ID.
            db.execute('UPDATE pending SET batch_id=NULL WHERE batch_id=?', (batch_id,))
            return moved

    def count(self):
        with self.connect() as db:
            return db.execute('SELECT count(*) FROM pending').fetchone()[0]
