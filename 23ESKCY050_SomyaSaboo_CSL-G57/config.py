from pathlib import Path
BASE_DIR=Path(__file__).resolve().parent
DB_PATH=BASE_DIR/'data'/'scans.db'; KEY_DIR=BASE_DIR/'keys'
PRIVATE_KEY=KEY_DIR/'signing_private.pem'; PUBLIC_KEY=KEY_DIR/'signing_public.pem'
HOST='127.0.0.1'; PORT=8000
