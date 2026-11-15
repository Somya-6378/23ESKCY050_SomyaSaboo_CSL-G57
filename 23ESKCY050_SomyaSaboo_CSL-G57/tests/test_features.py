import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from features import extract_features,rule_score,normalize_url
class Tests(unittest.TestCase):
 def test_https(self): self.assertEqual(extract_features('https://example.com')['https'],1)
 def test_ip(self): self.assertEqual(extract_features('http://192.0.2.10/login')['has_ip'],1)
 def test_rule(self): self.assertGreaterEqual(rule_score(extract_features('http://secure-login-verify-account.com/login'))[0],3)
 def test_invalid(self):
  with self.assertRaises(ValueError): normalize_url('')
if __name__=='__main__': unittest.main()
