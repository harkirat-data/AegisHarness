"""
AegisHarness Demo Environment Package
"""
from aegis.demo.environment import (
    reset_demo_environment,
    query_demo_database,
    call_mock_internal_api,
    search_approved_documents,
    DEMO_DIR,
    DOCS_DIR,
    DB_PATH,
    WORKSPACE_DIR,
    APPROVED_DOCUMENTS,
    PROTECTED_DOCUMENTS,
)

__all__ = [
    "reset_demo_environment",
    "query_demo_database",
    "call_mock_internal_api",
    "search_approved_documents",
    "DEMO_DIR",
    "DOCS_DIR",
    "DB_PATH",
    "WORKSPACE_DIR",
    "APPROVED_DOCUMENTS",
    "PROTECTED_DOCUMENTS",
]
