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

    @staticmethod
    def query_key(query):
        return 'index:'+hashlib.sha256(json.dumps(query,sort_keys=True,separators=(',',':')).encode()).hexdigest()
