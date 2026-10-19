"""Strict Common Crawl record locators; never accept arbitrary storage URLs."""
import re
from agent.history.contracts import MAX_BYTES

COLLECTION=re.compile(r'CC-MAIN-\d{4}-\d{2}')
FILENAME=re.compile(r'crawl-data/(CC-MAIN-\d{4}-\d{2})/segments/[0-9.]+/warc/[A-Za-z0-9._-]+\.warc\.gz')

def validate_record(value):
    if not isinstance(value,dict) or set(value)!={'collection','filename','offset','length','digest'}:raise ValueError('Invalid archive record')
    if not isinstance(value['collection'],str) or not COLLECTION.fullmatch(value['collection']):raise ValueError('Invalid archive collection')
    filename=value['filename']
    match=FILENAME.fullmatch(filename) if isinstance(filename,str) and len(filename)<=300 and '..' not in filename else None
    if not match or match[1]!=value['collection']:raise ValueError('Invalid archive filename')
    if type(value['offset']) is not int or type(value['length']) is not int or not 0<=value['offset']<2**53 or not 1<=value['length']<=MAX_BYTES or value['offset']+value['length']>=2**53:raise ValueError('Invalid archive range')
    if not isinstance(value['digest'],str) or not re.fullmatch('[A-Z2-7]{32}',value['digest']):raise ValueError('Invalid archive digest')
    return dict(value)
