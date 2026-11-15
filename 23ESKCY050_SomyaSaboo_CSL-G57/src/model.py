import random
from sklearn.ensemble import RandomForestClassifier
from features import extract_features,FEATURE_NAMES
def train_model():
 rng=random.Random(57); X=[]; y=[]
 safe=['example.com','wikipedia.org','python.org','skit.ac.in','github.com','docs.python.org','university.edu']
 bad=['secure-login-verify-account.com','bank-update-confirm.net','free-gift-wallet-login.xyz','xn--paypa1-4ve.com','192.0.2.10']
 for _ in range(700):
  if rng.random()<.5:
   host=rng.choice(safe); url=rng.choice(['https://','https://www.'])+host+rng.choice(['/','/about','/docs','/products?id=2']); label=0
  else:
   host=rng.choice(bad); url=rng.choice(['http://','https://'])+host+rng.choice(['/login/verify','/account/update?user=x','/secure/free-gift','/@signin']); label=1
   if rng.random()<.3: url='http://a.b.c.'+host+'/login?verify=1'
  f=extract_features(url); X.append([f[k] for k in FEATURE_NAMES]); y.append(label)
 model=RandomForestClassifier(n_estimators=120,max_depth=8,random_state=57,class_weight='balanced'); model.fit(X,y); return model
