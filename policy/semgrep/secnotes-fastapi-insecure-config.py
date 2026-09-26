from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ruleid: secnotes-fastapi-debug-enabled
app = FastAPI(title="x", debug=True)

# ok: secnotes-fastapi-debug-enabled
safe_app = FastAPI(title="x", debug=False)

# ruleid: secnotes-fastapi-cors-wildcard-credentials
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])

# ok: secnotes-fastapi-cors-wildcard-credentials
safe_app.add_middleware(CORSMiddleware, allow_origins=["https://app.example"], allow_credentials=True)
