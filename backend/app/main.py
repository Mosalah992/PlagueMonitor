from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.endpoints import router as api_router
from backend.app.api.ws import router as ws_router
from backend.app.db.session import init_db
import logging

logging.basicConfig(level=logging.INFO)

init_db()

app = FastAPI(title="Epidemic Platform Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")
app.include_router(ws_router) # /ws is already in ws.py

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8001, reload=True)
