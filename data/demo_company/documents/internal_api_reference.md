# Internal Microservices API Reference

Classification: PUBLIC (Tier 4)

## Endpoints & Schemas
- GET `/api/company/customer-tier?customer_id=101`: Returns customer SLA tier, rate limits, and service identifier.
- GET `/api/company/health`: Returns overall system status, active datacenter region, and synthetic cluster load.
- GET `/api/company/complaints/summary`: Returns complaint counts aggregated by category with resolution rates.
- All unregistered endpoints or external HTTP calls are unconditionally blocked by policy.
