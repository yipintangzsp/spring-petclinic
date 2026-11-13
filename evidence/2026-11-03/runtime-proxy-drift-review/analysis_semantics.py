"""ANALYSIS ONLY. Does not replace any checkpoint byte hash or accept live drift.
No field exclusions. Object key order/whitespace normalize; array order retained.
"""
import json,hashlib

def unique_object(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise ValueError('DUPLICATE_JSON_KEY')
  d[k]=v
 return d

def parse(text):return json.loads(text,object_pairs_hook=unique_object,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('NONFINITE_JSON')))
def canonical_digest(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
def analyse_text(text):return canonical_digest(parse(text))
def exposure(inbounds):
 return any(x.get('listen') not in ['127.0.0.1','::1','localhost'] for x in inbounds)
