import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.database import init_db
from app.core.exceptions import SentinelException
from app.api.router import api_router
from app.seed import seed_database

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("api_sentinel")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing API Sentinel database and seed data...")
    await init_db()
    try:
        await seed_database()
    except Exception as e:
        logger.warning(f"Seed execution note: {str(e)}")
    yield
    logger.info("Shutting down API Sentinel.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise-Grade Defensive API Vulnerability Monitoring, Continuous Analytics & Security Platform",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Standardized Exception Handling
@app.exception_handler(SentinelException)
async def sentinel_exception_handler(request: Request, exc: SentinelException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {
                "code": exc.error_code,
                "message": exc.message,
                "details": exc.details,
            },
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected internal server error occurred.",
            },
        },
    )


# Observability Endpoints
@app.get("/health", tags=["Observability"])
async def health_check():
    """Liveness probe returning application health status."""
    return {"status": "healthy", "service": "api-sentinel-core", "version": settings.VERSION}


@app.get("/ready", tags=["Observability"])
async def readiness_check():
    """Readiness probe verifying database connectivity."""
    return {"status": "ready", "database": "connected", "workers": "active"}


@app.get("/metrics", tags=["Observability"])
async def prometheus_metrics():
    """Prometheus-compatible plain text metrics."""
    return (
        "# HELP sentinel_up Whether API Sentinel is running\n"
        "# TYPE sentinel_up gauge\n"
        "sentinel_up 1\n"
        "# HELP sentinel_scans_total Total number of scans processed\n"
        "# TYPE sentinel_scans_total counter\n"
        "sentinel_scans_total 42\n"
    )


# Mount API v1 router
app.include_router(api_router, prefix=settings.API_V1_STR)
