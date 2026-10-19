"""Private, transactional history checkpoints scoped to a single admitted scan."""
import hashlib
import json
import time


class HistoryState:
    def __init__(self, registry, scan_id, scope):
        self.registry, self.scan_id, self.scope = registry, scan_id, scope
        with registry.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS history_state (
                scan_id TEXT NOT NULL, scope TEXT NOT NULL, name TEXT NOT NULL,
                value TEXT NOT NULL, updated_at REAL NOT NULL,
                PRIMARY KEY(scan_id,name),
                FOREIGN KEY(scan_id) REFERENCES history_jobs(scan_id) ON DELETE CASCADE)''')

    def get(self, name):
        with self.registry.connect() as db:
            row=db.execute('SELECT scope,value FROM history_state WHERE scan_id=? AND name=?',(self.scan_id,name)).fetchone()
        if not row:return None
        if row['scope']!=self.scope:raise ValueError('Historical checkpoint scope mismatch')
        return json.loads(row['value'])

    def put(self, name, value):
        encoded=json.dumps(value,separators=(',',':'),sort_keys=True)
        if len(encoded)>64_000_000:raise ValueError('Historical checkpoint exceeds storage budget')
        with self.registry.connect() as db:
            db.execute('''INSERT INTO history_state VALUES(?,?,?,?,?) ON CONFLICT(scan_id,name)
                DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at
                WHERE history_state.scope=excluded.scope''',(self.scan_id,self.scope,name,encoded,time.time()))

    def event_timestamp(self, identity, timestamp):
        """Freeze an evidence envelope's timestamp before its first outbox append.

        Replaying a checkpoint must reproduce the same bytes even while the first
        delivery is still queued. Keep the outbox's collision check strict.
        """
        if len(identity)!=64 or any(c not in '0123456789abcdef' for c in identity) or type(timestamp) is not int or timestamp<=0:
            raise ValueError('Invalid historical event identity')
        with self.registry.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            name='event:'+identity
            db.execute('INSERT OR IGNORE INTO history_state VALUES(?,?,?,?,?)',
                       (self.scan_id,self.scope,name,json.dumps(timestamp),time.time()))
            row=db.execute('SELECT scope,value FROM history_state WHERE scan_id=? AND name=?',(self.scan_id,name)).fetchone()
            saved=json.loads(row['value'])
            if row['scope']!=self.scope or type(saved) is not int or saved<=0:
                raise ValueError('Invalid historical event checkpoint')
            return saved

    @staticmethod
    def query_key(query):
        return 'index:'+hashlib.sha256(json.dumps(query,sort_keys=True,separators=(',',':')).encode()).hexdigest()
