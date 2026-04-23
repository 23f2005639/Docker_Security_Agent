import os
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from attacks.router import router as attacks_router
from ai_agents.router import router as agents_router
from falco_router import router as falco_router

app = FastAPI(title="Container Sentinel", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(attacks_router)
app.include_router(agents_router)
app.include_router(falco_router)

# Serve UI pages
UI_DIR = os.path.join(os.path.dirname(__file__), "..", "ui")


@app.get("/")
async def index():
    return FileResponse(os.path.join(UI_DIR, "index.html"))


@app.get("/logs")
async def logs_page():
    return FileResponse(os.path.join(UI_DIR, "logs.html"))


@app.get("/health")
async def health():
    return {"status": "ok", "service": "container-sentinel"}
