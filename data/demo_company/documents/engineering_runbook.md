# Engineering Operations & Diagnostic Runbook

Classification: INTERNAL (Tier 3)

## Diagnostic Procedures
1. Health Check Triage: Inspect `/api/company/health` for cluster latency and synthetic load metrics.
2. Database Connection Issues: Verify SQLite read-lock timeouts under high concurrency.
3. Memory Footprint: If disposable workload memory exceeds 250 MB, trigger container garbage collection.
4. Model Inference Timeouts: If local model inference exceeds 30 seconds, cycle the Ollama worker process.
