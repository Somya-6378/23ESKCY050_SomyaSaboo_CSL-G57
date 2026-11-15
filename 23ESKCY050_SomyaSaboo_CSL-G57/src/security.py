import hashlib,hmac,json
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from config import KEY_DIR,PRIVATE_KEY,PUBLIC_KEY
AUDIT_SECRET=b'CSL-G57-local-demo-key-change-before-deployment'
def init_keys():
 KEY_DIR.mkdir(exist_ok=True)
 if not PRIVATE_KEY.exists():
  k=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  PRIVATE_KEY.write_bytes(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
  PUBLIC_KEY.write_bytes(k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
def canonical(d): return json.dumps(d,sort_keys=True,separators=(',',':')).encode()
def sign_receipt(d):
 init_keys(); k=serialization.load_pem_private_key(PRIVATE_KEY.read_bytes(),password=None)
 return k.sign(canonical(d),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()).hex()
def verify_receipt(d,s):
 init_keys(); k=serialization.load_pem_public_key(PUBLIC_KEY.read_bytes())
 try: k.verify(bytes.fromhex(s),canonical(d),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()); return True
 except Exception: return False
def audit_mac(digest,verdict,created): return hmac.new(AUDIT_SECRET,f'{digest}|{verdict}|{created}'.encode(),hashlib.sha256).hexdigest()
