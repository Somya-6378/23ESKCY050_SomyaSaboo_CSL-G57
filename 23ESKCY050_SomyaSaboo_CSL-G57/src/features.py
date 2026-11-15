import ipaddress,re
from urllib.parse import urlparse
SHORTENERS={'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly'}
TOKENS=('login','verify','account','secure','update','password','bank','wallet','confirm','signin','free','gift')
def normalize_url(value):
 value=value.strip()
 if not value: raise ValueError('Please enter a URL')
 if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://',value): value='http://'+value
 p=urlparse(value)
 if p.scheme not in ('http','https') or not p.hostname: raise ValueError('Enter a valid HTTP or HTTPS URL')
 return value,p
def extract_features(value):
 value,p=normalize_url(value); host=(p.hostname or '').lower()
 try: ipaddress.ip_address(host); is_ip=1
 except ValueError: is_ip=0
 labels=host.split('.'); text=value.lower()
 return {'url_length':len(value),'host_length':len(host),'https':int(p.scheme=='https'),'has_ip':is_ip,'at_symbol':int('@' in value),'hyphen_count':host.count('-'),'dot_count':host.count('.'),'subdomain_count':max(0,len(labels)-2),'suspicious_token_count':sum(t in text for t in TOKENS),'shortener':int(host in SHORTENERS),'punycode':int('xn--' in host),'port_present':int(p.port is not None),'query_count':len(p.query.split('&')) if p.query else 0,'path_length':len(p.path),'double_slash_path':int('//' in p.path)}
FEATURE_NAMES=list(extract_features('https://example.com').keys())
def rule_score(f):
 checks=[(f['https']==0,1,'Uses HTTP rather than HTTPS'),(f['has_ip']==1,2,'Uses an IP address as host'),(f['at_symbol']==1,2,'Contains @ in URL'),(f['url_length']>75,1,'Unusually long URL'),(f['hyphen_count']>=2,1,'Multiple hyphens in host'),(f['subdomain_count']>=3,1,'Many subdomains'),(f['suspicious_token_count']>=2,1,'Contains multiple sensitive/action words'),(f['shortener']==1,1,'Uses a URL-shortening domain'),(f['punycode']==1,2,'Contains punycode hostname')]
 reasons=[reason for cond,points,reason in checks if cond]; return sum(points for cond,points,_ in checks if cond),reasons
