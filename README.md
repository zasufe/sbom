# SBOM FastAPI Migration (sbom module)

This is a **FastAPI** migration of the Flask `sbom` module you provided.

## Key points
- **All API paths are kept identical** (e.g. `/change/create_sbom_project`).
- **Request parameters are kept identical**:
  - `create_sbom_project`: multipart `project_name/project_desc/code_language` + `file`
  - other endpoints: JSON body models (Pydantic)
- **User authentication removed** as requested. Internally a constant `DEFAULT_USER_ID=0` is used to preserve per-user filtering behavior in the DB layer.
- SQLAlchemy uses **2.0 style engine** and a FastAPI dependency (`Depends(get_db)`).

## Run
```bash
# source .venv/bin/activate

uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## Config
Environment variables:
- `DATABASE_URI`
- `SBOM_STORAGE_DIR` (default: `./src/data/sbom`)
- `DX_API_HOST` (default: `http://127.0.0.1:8080`)
- `DX_API_KEY`
