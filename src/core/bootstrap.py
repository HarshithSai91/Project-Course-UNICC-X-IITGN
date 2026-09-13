"""
Team 2 Live Bootstrap — dependency injection for real retrieval.

Constructs real Koushik/Suhani dependencies and wires UpstreamRetrievalBackend.
No hardcoded personal paths; uses configurable UPSTREAM_MODULE_PATH or PYTHONPATH.
Fails clearly when required teammate objects are unavailable.
"""
from __future__ import annotations

import sys
import sqlite3
import importlib.util
import os
from typing import Any

from src.core.interfaces import RetrievalBackend, MockRetrievalBackend, set_backend, MissingUpstreamDependency
from src.core.config import get_settings
from src.adapters.upstream_adapter import UpstreamRetrievalBackend


def _import_upstream(mod_name: str, module_path: str | None = None):
    """Try to import upstream module from PYTHONPATH or configurable path."""
    try:
        return __import__(mod_name)
    except ImportError:
        pass
    if module_path and os.path.isdir(module_path):
        for root, _, files in os.walk(module_path):
            for f in files:
                if f == f"{mod_name}.py":
                    full = os.path.join(root, f)
                    spec = importlib.util.spec_from_file_location(mod_name, full)
                    if spec and spec.loader:
                        mod = importlib.util.module_from_spec(spec)
                        sys.modules[mod_name] = mod
                        spec.loader.exec_module(mod)
                        return mod
    return None


def build_live_backend() -> Any:
    settings = get_settings()
    upstream_path = settings.UPSTREAM_MODULE_PATH or os.environ.get("UPSTREAM_MODULE_PATH", "")
    # Attempt to import upstream hybrid_search module
    upstream_hybrid = _import_upstream("hybrid_search", upstream_path)
    if upstream_hybrid is None:
        # Try adding upstream repo to sys.path temporarily for import
        try:
            import site
            site_path = upstream_path  # must be configured via settings/env; do not hardcode
            # Only use site_path if it exists; otherwise fail clearly
            if site_path and os.path.isdir(site_path) and site_path not in sys.path:
                sys.path.insert(0, site_path)
            upstream_hybrid = __import__("hybrid_search")
        except Exception:
            upstream_hybrid = None
    if upstream_hybrid is None:
        raise MissingUpstreamDependency(
            "Upstream hybrid_search module not available. "
            "Set UPSTREAM_MODULE_PATH env/config to teammate repo, or use RETRIEVAL_BACKEND=mock."
        )
    # Try to construct dependencies using upstream setup if available
    # Note: real Qdrant/SQLite/BM25 instances require actual DB/files from teammate pipeline.
    # This bootstrap attempts to build them when present; if DB/files missing, raises clearly.
    try:
        # Try upstream setup_databases (vector_database)
        vd = _import_upstream("vector_database", upstream_path)
        if vd is not None and hasattr(vd, "setup_databases"):
            qdrant, sqlite = vd.setup_databases()
        else:
            # Cannot initialize without upstream storage setup
            raise MissingUpstreamDependency(
                "Upstream setup_databases not available; Qdrant + SQLite not initialized. "
                "Provide actual teammate storage or inject qdrant/sqlite objects manually."
            )
    except MissingUpstreamDependency:
        raise
    except Exception as exc:
        raise MissingUpstreamDependency(
            f"Failed to initialize upstream Qdrant/SQLite: {exc}. "
            "Confirm teammate storage is accessible at configured UPSTREAM_MODULE_PATH."
        ) from exc
    # BM25 index from upstream bm25_index
    try:
        bm25_mod = _import_upstream("bm25_index", upstream_path)
        if bm25_mod is None or not hasattr(bm25_mod, "BM25Index"):
            raise MissingUpstreamDependency("Upstream BM25Index module unavailable.")
        # In real deployment, build BM25Index from sqlite database contents
        # For standalone repo without actual corpus DB, this will fail clearly
        bm25 = bm25_mod.BM25Index()  # Requires real index build; will fail if DB missing
    except Exception as exc:
        raise MissingUpstreamDependency(
            f"Failed to build BM25 index: {exc}. "
            "Confirm teammate BM25 index is available or inject bm25_index directly."
        ) from exc
    # Encoder from upstream vectorizer or default
    try:
        vectorizer = _import_upstream("vectorizer", upstream_path)
        if vectorizer is not None and hasattr(vectorizer, "default_query_encoder"):
            query_encoder = vectorizer.default_query_encoder
        else:
            raise MissingUpstreamDependency("Upstream query_encoder missing: provide BGE-M3 encoder or inject query_encoder.")
    except MissingUpstreamDependency:
        raise
    except Exception as exc:
        raise MissingUpstreamDependency(
            f"Failed to load query encoder: {exc}."
        ) from exc
    # Assemble real HybridSearcher
    try:
        HybridSearcher = getattr(upstream_hybrid, "HybridSearcher", None)
        if HybridSearcher is None:
            raise MissingUpstreamDependency("HybridSearcher class not found in upstream module.")
        hybrid_searcher = HybridSearcher(
            qdrant=qdrant,
            sqlite=sqlite,
            bm25=bm25,
            query_encoder=query_encoder,
        )
    except Exception as exc:
        raise MissingUpstreamDependency(
            f"Failed to construct HybridSearcher: {exc}. "
            "Injectable dependencies: qdrant_client, sqlite_connection, bm25_index, query_encoder."
        ) from exc
    # Build adapter with real instances
    return UpstreamRetrievalBackend(
        hybrid_searcher=hybrid_searcher,
        sqlite_connection=sqlite,
        fetch_chunk_metadata=getattr(vd, "fetch_chunk_metadata", None),
        exact_lookup=getattr(_import_upstream("exact_lookup", upstream_path) or None, "exact_lookup", None),
    )


def bootstrap_retrieval(settings) -> Any:
    """Factory called by main.py lifespan for RETRIEVAL_BACKEND=live."""
    mode = getattr(settings, "RETRIEVAL_BACKEND", "mock")
    if mode == "mock":
        from src.core.interfaces import MockRetrievalBackend
        return MockRetrievalBackend()
    if mode == "live":
        return build_live_backend()
    raise ValueError(f"Unknown RETRIEVAL_BACKEND: {mode}")
