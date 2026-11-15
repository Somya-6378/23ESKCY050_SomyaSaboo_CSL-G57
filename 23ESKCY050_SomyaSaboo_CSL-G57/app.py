from http.server import BaseHTTPRequestHandler,HTTPServer
from urllib.parse import parse_qs
from datetime import datetime,timezone
import html,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'src'))
from features import extract_features,FEATURE_NAMES,rule_score,normalize_url
from model import train_model
from storage import init_db,save_scan,recent_scans
from security import sign_receipt,verify_receipt
from config import HOST,PORT
MODEL=train_model(); init_db()
CSS="""*{box-sizing:border-box}body{margin:0;background:#eef3f9;color:#17243a;font:15px Arial}.top{background:#102a43;color:white;padding:20px max(calc((100% - 980px)/2),24px)}.top small{color:#b9d5ee}.wrap{max-width:980px;margin:30px auto;padding:0 20px}.card{background:white;border:1px solid #dbe4ef;border-radius:14px;padding:24px;margin:16px 0;box-shadow:0 5px 18px #102a4310}h1{margin:0 0 6px;font-size:25px}h2{font-size:18px}.muted{color:#61738a}.input{width:100%;padding:15px;border:1px solid #bdcbdc;border-radius:8px;font-size:16px;margin:10px 0 14px}.btn{background:#1769aa;color:white;border:0;border-radius:8px;padding:13px 20px;font-weight:bold;cursor:pointer}.pill{display:inline-block;padding:7px 12px;border-radius:20px;font-weight:bold}.safe{background:#d9f6e7;color:#11643b}.risk{background:#ffe4df;color:#9a281a}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.metric{background:#f3f7fb;border-radius:9px;padding:14px}.metric b{display:block;font-size:21px;margin-top:5px}li{margin:7px 0}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:9px;border-bottom:1px solid #e5ebf2;font-size:13px;overflow-wrap:anywhere}.foot{color:#728198;text-align:center;font-size:12px;padding:24px}@media(max-width:650px){.grid{grid-template-columns:1fr}}"""
def page(body): return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PhishGuard | CSL-G57</title><style>'+CSS+'</style></head><body><div class="top"><b>◈ PhishGuard</b> <span style="float:right">CSL-G57 · Cyber Security Lab</span><br><small>Rule-based + machine-learning URL risk checker</small></div><main class="wrap">'+body+'</main><div class="foot">Educational prototype · URLs are analysed locally and are never opened or fetched.</div></body></html>'
def esc(x): return html.escape(str(x))
def home(result=None,error=None):
 b='<section class="card"><h1>Check a suspicious link</h1><p class="muted">Paste a URL to inspect lexical indicators before opening it. This tool does not visit the destination.</p><form method="POST" action="/scan"><label for="url"><b>Website URL</b></label><input class="input" id="url" name="url" placeholder="https://example.com/login" required><button class="btn">Analyse URL securely →</button></form><small class="muted">Use harmless examples or fabricated test strings.</small></section>'
 if error: b+='<section class="card"><b style="color:#a22">Input error:</b> '+esc(error)+'</section>'
 if result:
  v=result['verdict']; cl='risk' if v=='POTENTIAL PHISHING' else 'safe'
  b+='<section class="card"><h2>Analysis result</h2><span class="pill '+cl+'">'+v+'</span><p class="muted">Educational estimate, not a guarantee. Verify links through a trusted channel.</p><div class="grid"><div class="metric">Rule score<b>'+str(result['score'])+'</b></div><div class="metric">ML probability<b>'+str(round(result['prob']*100,1))+'%</b></div><div class="metric">Combined decision<b>Review</b></div></div><h2>Triggered indicators</h2><ul>'+(''.join('<li>'+esc(x)+'</li>' for x in result['reasons']) if result['reasons'] else '<li>No configured rule triggered.</li>')+'</ul><h2>Signed scan receipt (RSA-PSS / SHA-256)</h2><textarea class="input" rows="3" readonly>'+esc(result['signature'])+'</textarea><p><b>Signature verification:</b> <span class="pill safe">VALID</span></p><small class="muted">Only SHA-256 URL digest is stored; plaintext URL is not saved.</small></section>'
 rows=recent_scans(); b+='<section class="card"><h2>Recent scan history (local)</h2><table><tr><th>ID</th><th>URL SHA-256</th><th>Decision</th><th>Rule</th><th>ML</th><th>UTC</th></tr>'
 for r in rows: b+='<tr><td>'+str(r[0])+'</td><td>'+esc(r[1][:16])+'…</td><td>'+esc(r[2])+'</td><td>'+str(r[3])+'</td><td>'+str(round(r[4]*100,1))+'%</td><td>'+esc(r[5])+'</td></tr>'
 b+='</table></section><section class="card"><h2>Security notes</h2><ul><li>No DNS lookup or HTTP request is made.</li><li>History stores SHA-256 digest and HMAC audit value.</li><li>Receipts are digitally signed with a local RSA keypair.</li><li>Production requires HTTPS/TLS and protected key management.</li></ul></section>'
 return page(b)
class Handler(BaseHTTPRequestHandler):
 def send(self,c,status=200):
  d=c.encode(); self.send_response(status); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(d))); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Referrer-Policy','no-referrer'); self.end_headers(); self.wfile.write(d)
 def do_GET(self): self.send(home() if self.path=='/' else ('OK' if self.path=='/health' else 'Not found'),404 if self.path not in ('/','/health') else 200)
 def do_POST(self):
  if self.path!='/scan': self.send('Not found',404); return
  n=int(self.headers.get('Content-Length','0')); form=parse_qs(self.rfile.read(min(n,10000)).decode('utf-8','replace')); url=form.get('url',[''])[0]
  try:
   clean,_=normalize_url(url); f=extract_features(clean); score,reasons=rule_score(f); prob=float(MODEL.predict_proba([[f[k] for k in FEATURE_NAMES]])[0][1]); verdict='POTENTIAL PHISHING' if score>=3 or prob>=.55 else 'LOW RISK'
   now=datetime.now(timezone.utc).isoformat(timespec='seconds'); digest,mac=save_scan(clean,verdict,score,prob,now); receipt={'url_sha256':digest,'verdict':verdict,'rule_score':score,'ml_probability':round(prob,6),'created_at':now,'audit_hmac':mac}; sig=sign_receipt(receipt); assert verify_receipt(receipt,sig)
   self.send(home({'verdict':verdict,'score':score,'prob':prob,'reasons':reasons,'signature':sig}))
  except Exception as e: self.send(home(error=str(e)),400)
 def log_message(self,*a): pass
if __name__=='__main__': print(f'PhishGuard at http://{HOST}:{PORT}'); HTTPServer((HOST,PORT),Handler).serve_forever()
