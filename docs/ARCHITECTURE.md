# Adaptive Cyber Defense Framework — Architecture Specification

This document details the architectural design and system workflows of the integrated Adaptive Cyber Defense Framework.

## Architecture Diagram

```text
Frontend (React + Vite + TypeScript)
   |
   v
FastAPI Backend Core Engine
   |
   +---- Authentication (JWT & Token Blacklisting)
   |
   +---- MTD Middleware (Dynamic Routing & Decoy Interception)
   |
   +---- Threat Correlation & Adaptive Risk Engine
   |
   +---- Threat Mitigation (Automated IP Blocking)
   |
   +---- Security Alerts & Audit Logging API
   |
   v
PostgreSQL / SQLite Database
```

---

## 1. Moving Target Defense (MTD) & Security Flow

The system protects sensitive endpoints from targeted scanners and attackers by dynamically translating routing spaces.

### Legitimate Request Flow
```text
Request (Legitimate)
   |
   v
[MTD Middleware] 
   |---> Check if request matches current dynamic path map (e.g. /api/v1/d/c9f80a42)
   |---> Decode dynamic path -> Real endpoint (e.g. /api/v1/auth/me)
   |---> Rewrite ASGI scope path
   |
   v
[FastAPI Routing & Controllers]
   |
   v
Response returned to user
```

### Attacker / Decoy Trigger Flow
```text
Attacker Request (Decoy / Real Endpoint Direct Access)
   |
   v
[MTD Middleware]
   |---> Check if request matches decoy paths (e.g. /api/v1/system/env)
   |---> OR direct check to real protected paths (e.g. /api/v1/auth/me) without translation
   |---> Intercept request
   |---> Extract telemetry: IP, User-Agent, Headers
   |---> Log to DB (HoneypotLog table) & feed into Threat Correlation Risk Engine
   |
   v
Response returned: Fake 404 error (No details revealed)
```

---

## 2. Threat Correlation & Risk Engine

The system correlates raw security signals from multiple modules to calculate real-time threat scores per client IP:

1. **Signal Aggregation**: Auth failures, honeypot hits, direct protected path access, expired alias hits, and token tampering events are captured.
2. **Weighted Scoring**: Each event type incurs a weighted penalty score.
3. **Time-Based Decay**: Inactive threat scores decay automatically over time.
4. **Adaptive Response**:
   - **MEDIUM Risk**: Increases telemetry logging.
   - **HIGH Risk**: Triggers automated 5-minute IP block.
   - **CRITICAL Risk**: Triggers 30-minute IP isolation, token invalidation, and external notifications.
