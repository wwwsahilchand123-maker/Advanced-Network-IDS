# Windows Run Guide

## Backend

Open a VS Code terminal at `backend`:

```powershell
python -m venv venv
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Then configure `.env`. For a local development setup, use SQLite if the code/config
supports it; PostgreSQL and Redis are the documented production-style services.

Start the API:

```powershell
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open:

- `http://localhost:8000`
- `http://localhost:8000/api/v1/docs`

## Frontend

Open a second VS Code terminal:

```powershell
cd frontend
npm install
npm run dev
```

The frontend configuration targets port 3000 and proxies `/api` to the backend.

## Important

Packet capture may require elevated privileges and a valid network interface.
Use the capture/detection features only on systems and networks you are authorized
to monitor.

If a command fails, stop at that step and inspect the exact error before changing
the project files.
