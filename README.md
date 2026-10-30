# Adaptive Cyber Defense Framework

Adaptive Cyber Defense is a full-stack, enterprise cyber defense framework. It integrates **Moving Target Defense (MTD)** dynamic API route rotation, **honeypot decoy traps**, **adaptive risk scoring**, and **real-time security incident analytics**.

---

## 1. System Architecture

For a detailed analysis of workflows, refer to the [ARCHITECTURE.md](docs/ARCHITECTURE.md) document.

* **Frontend**: React, Vite, TypeScript, TailwindCSS, Zustand, Lucide icons, Framer Motion, and Axios.
* **Backend**: FastAPI, Python 3.10+, SQLAlchemy, Alembic migrations, and Uvicorn.
* **Database**: PostgreSQL (Dockerized) or SQLite (local developer fallback).

### Frontend Features
* **Light Enterprise Theme**: A clean, professional, and dense information design utilizing white backgrounds, light gray borders, and a primary blue (#2563EB) accent.
* **Icon Navigation Rail**: A slim, responsive 68px sidebar presenting icons with accessible tooltips, freeing up dashboard space for data.
* **Command Palette**: A global Cmd/Ctrl + K interface using cmdk for rapid route and action discovery.
* **Motion & Animations**: Subtle framer-motion scroll reveals and route transitions, combined with a performant pure-CSS animated gradient mesh background. Features full prefers-reduced-motion accessibility support.

---

## 2. Prerequisites

* **Docker & Docker Compose** (for running the full stack)
* **Python 3.10 or 3.11** (for local backend development)
* **Node.js 18 or 20** (for local frontend development)

---

## 3. Environment Setup

Copy `.env.example` to `.env` in the root directory:

```bash
cp .env.example .env
```

Review and adjust variables as needed:
* `DATABASE_URL`: PostgreSQL connection string.
* `JWT_SECRET_KEY`: Random secret string for JWT access tokens.
* `JWT_REFRESH_SECRET_KEY`: Random secret string for JWT refresh tokens.
* `MTD_ENABLED`: Toggle MTD route protection.

---

## 4. Running the System

### Option A: Using Docker Compose (Recommended)

To run the database, backend, and frontend concurrently:

```bash
docker compose up --build
```

Access the applications:
* **Frontend UI**: [http://localhost:8080](http://localhost:8080)
* **Backend API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)

### Option B: Local Development Setup

#### 1. Start the Database
Either run a local PostgreSQL service or let the backend automatically fall back to its SQLite database (`backend/app.db`) for developer ease.

#### 2. Run Backend API
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python -m pytest   # Run tests
uvicorn app.main:app --reload
```

#### 3. Run Frontend Dev Server
```bash
cd frontend
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173).

---

## 5. Testing

### Run Backend Tests
Run the pytest suite inside the activated backend virtual environment:

```bash
cd backend
python -m pytest
```

Included test categories:
1. JWT register, login, refresh, logout, token blacklist.
2. Moving Target Defense status query and manual rotations.
3. Honey decoy path interceptions and database persistence.
4. Security alert generation, cooldown, and status resolution.
5. Adaptive threat correlation and risk engine scoring.
