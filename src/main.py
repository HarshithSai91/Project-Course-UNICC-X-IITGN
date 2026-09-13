import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import entities, health, search, threats
from src.core.config import get_settings

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # Startup: Initialize connections to Qdrant, Neo4j, etc.
    settings = get_settings()
    print(f"Starting up Threat Retrieval & Matching Subsystem (backend={settings.RETRIEVAL_BACKEND})...")
    if settings.RETRIEVAL_BACKEND == "live":
        try:
            from src.core import bootstrap
            live_backend = bootstrap.build_live_backend()
            set_backend(live_backend)
            print("Upstream adapter registered (live dependencies injected).")
        except Exception as exc:
            print(f"Live retrieval backend initialization failed: {exc}")
            raise RuntimeError(
                "RETRIEVAL_BACKEND=live requested but teammate dependencies unavailable. "
                "Provide upstream Qdrant/SQLite/BM25/encoder instances or use RETRIEVAL_BACKEND=mock."
            ) from exc
            raise
    yield
    # Shutdown: Clean up connections
    print("Shutting down Threat Retrieval & Matching Subsystem...")


app = FastAPI(
    title="Threat Retrieval & Matching Subsystem",
    description="Backend & Intelligence Microservice for Threat Retrieval",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json"
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Process latency header middleware
@app.middleware("http")
async def add_process_time_header(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start_time
    response.headers["X-Process-Time-ms"] = str(round(process_time * 1000, 2))
    return response


# Include routers
from src.api.routes import team3
app.include_router(team3.router, prefix=settings.API_PREFIX, tags=["Team 3"])
app.include_router(health.router, prefix=settings.API_PREFIX, tags=["System"])
app.include_router(entities.router, prefix=settings.API_PREFIX, tags=["Entities"])
app.include_router(search.router, prefix=settings.API_PREFIX, tags=["Search"])
app.include_router(threats.router, prefix=settings.API_PREFIX, tags=["Threats"])
