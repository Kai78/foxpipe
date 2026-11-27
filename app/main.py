"""FastAPI application factory and lifecycle orchestration."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import AppConfig, load_config
from app.database import create_repository
from app.logging_config import configure_logging, get_logger
from app.routers.dashboard import router as dashboard_router
from app.routers.webhook import router as webhook_router
from app.worker import PipelineWorkerManager

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(config_path: str | Path | None = None) -> FastAPI:
    """Build and configure the FastAPI application."""
    config: AppConfig = load_config(config_path)

    application = FastAPI(
        title=config.server.app_title,
        version="1.0.0",
    )

    configure_logging(config)
    repository = create_repository(config)
    worker = PipelineWorkerManager(config=config, repository=repository)

    application.state.config = config
    application.state.repository = repository
    application.state.worker = worker

    @application.on_event("startup")
    def on_startup() -> None:
        db_info = repository.get_database_info()
        get_logger().info(
            "Webservice ready on %s:%s (engine=%s, target=%s).",
            config.server.host,
            config.server.port,
            db_info["engine"],
            db_info["path"],
        )

    @application.on_event("shutdown")
    def on_shutdown() -> None:
        get_logger().info("Shutting down background pipeline worker pool...")
        worker.shutdown(wait=True)

    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    application.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    application.include_router(webhook_router)
    application.include_router(dashboard_router)

    return application


app = create_app()
