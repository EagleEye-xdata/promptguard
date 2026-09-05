from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .database import Base, engine, get_db
from .config import settings
from .services.session_window import session_windows
from .api.inspect import inspect_session

# Import API routers
from .api.targets import router as targets_router
from .api.attacks import router as attacks_router
from .api.inspect import router as inspect_router
from .api.tests import router as tests_router
from .api.proxy import router as proxy_router
from .api.reports import router as reports_router
from .api.alerts import router as alerts_router

# Ensure tables exist
Base.metadata.create_all(engine)

app = FastAPI(
    title="eagleI — AI Security Testing & Inspection Platform",
    description="3-Panel Architecture: Injection -> Chatbox -> Analyzer",
    version="1.0.0"
)

# CORS Configuration
allowed_origins = [x.strip() for x in settings.cors_origins.split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.get("/health")
def health(db: Session = Depends(get_db)):
    return {
        "status": "ok",
        "database": "connected",
        "judge_provider": settings.judge_provider,
        "mode": "3-panel-unified"
    }


# Include Routers
app.include_router(targets_router)
app.include_router(attacks_router)
app.include_router(inspect_router)
app.include_router(tests_router)
app.include_router(proxy_router)
app.include_router(reports_router)
app.include_router(alerts_router)

__all__ = ["app", "inspect_session", "session_windows"]
