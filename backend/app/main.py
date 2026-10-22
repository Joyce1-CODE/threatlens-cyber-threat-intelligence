from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import init_db
from app.routers import health, investigate, stats, bulk
from app.ioc_validator import IOCValidationError

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    init_db()
    yield

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="ThreatLens AI — Passive Cyber Threat Intelligence and IOC Investigation Platform",
    lifespan=lifespan
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Custom exception handler for validation
@app.exception_handler(IOCValidationError)
async def ioc_validation_exception_handler(request: Request, exc: IOCValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": exc.message, "field": exc.field}
    )

# Register routers under /api
app.include_router(health.router, prefix="/api")
app.include_router(investigate.router, prefix="/api")
app.include_router(stats.router, prefix="/api")

app.include_router(bulk.router, prefix="/api")
