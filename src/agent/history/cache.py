"""Authenticated, expiring, size-bounded archive cache on the agent only."""
import base64
import hashlib
import hmac
import json
import time
from cryptography.fernet import Fernet, InvalidToken
from agent.history.contracts import permitted, MAX_BYTES


class ArchiveCache:
    MAX_BYTES=100_000_000
    TTL=7*24*3600

    def __init__(self,registry,target_id,scope,key,target,config):
        self.registry,self.target_id,self.scope,self.target,self.config=registry,target_id,scope,target,config
        derived=hmac.new(key,b'lhx-historical-cache-v1',hashlib.sha256).digest()
        self.cipher=Fernet(base64.urlsafe_b64encode(derived))
        with registry.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS history_cache (
                target_id TEXT NOT NULL, locator TEXT NOT NULL, expires REAL NOT NULL,
                stored REAL NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(target_id,locator))''')
            db.execute('DELETE FROM history_cache WHERE expires<=?',(time.time(),))
            db.execute('CREATE INDEX IF NOT EXISTS ix_history_cache_stored ON history_cache(stored)')

    def locator(self,capture):
        source=json.dumps({'provider':capture.get('archive_provider','wayback'),'record':capture.get('archive_record')},sort_keys=True,separators=(',',':'))
        return hashlib.sha256((self.scope+'|'+source+'|'+capture['original_url']+'|'+capture['requested_timestamp']).encode()).hexdigest()

    def get(self,capture):
        locator=self.locator(capture)
        with self.registry.connect() as db:
            row=db.execute('SELECT payload FROM history_cache WHERE target_id=? AND locator=? AND expires>? AND length(payload)<=16000000',(self.target_id,locator,time.time())).fetchone()
        if not row:return None
        try:
            value=json.loads(self.cipher.decrypt(row['payload']))
            if set(value)!={'content','actual','digest','bytes','content_digest','locator'} or value['locator']!=locator:raise ValueError()
            content=value['content']
            if not isinstance(content,str) or len(content.encode())>4*MAX_BYTES or type(value['bytes']) is not int or not 0<=value['bytes']<=MAX_BYTES:raise ValueError()
            if hashlib.sha256(content.encode()).hexdigest()!=value['content_digest']:raise ValueError()
            if not isinstance(value['digest'],str) or len(value['digest'])!=64 or any(c not in '0123456789abcdef' for c in value['digest']):raise ValueError()
            if not permitted(capture['original_url'],self.target,self.config,value['actual']):raise ValueError()
            return content,value['actual'],value['digest'],value['bytes']
        except (InvalidToken,ValueError,TypeError,KeyError,UnicodeError,RecursionError):
            with self.registry.connect() as db:db.execute('DELETE FROM history_cache WHERE target_id=? AND locator=?',(self.target_id,locator))
            return None

    def put(self,capture,result):
        content,actual,digest,size=result
        locator=self.locator(capture)
        value={'content':content,'actual':actual,'digest':digest,'bytes':size,'content_digest':hashlib.sha256(content.encode()).hexdigest(),'locator':locator}
        payload=self.cipher.encrypt(json.dumps(value,separators=(',',':')).encode())
        now=time.time()
        with self.registry.connect() as db:
            db.execute('DELETE FROM history_cache WHERE expires<=?',(now,))
            if len(payload)>self.MAX_BYTES:return
            db.execute('INSERT OR REPLACE INTO history_cache VALUES(?,?,?,?,?)',(self.target_id,locator,now+self.TTL,now,payload))
            total,count=db.execute('SELECT coalesce(sum(length(payload)),0),count(*) FROM history_cache').fetchone()
            if total>self.MAX_BYTES or count>4096:
                for row in db.execute('SELECT target_id,locator,length(payload) AS size FROM history_cache ORDER BY stored ASC').fetchall():
                    db.execute('DELETE FROM history_cache WHERE target_id=? AND locator=?',(row['target_id'],row['locator']))
                    total-=row['size']
                    count-=1
                    if total<=self.MAX_BYTES and count<=4096:break
