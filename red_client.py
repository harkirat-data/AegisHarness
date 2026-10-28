#!/usr/bin/env python
"""
AegisHarness Standalone Red Team CLI Entry Point
Run: python red_client.py --prompt "Query financial_records" --scope "database"
"""

from aegis.red.client import run_cli

if __name__ == "__main__":
    run_cli()
