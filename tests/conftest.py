from pathlib import Path
import sys
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app import create_app


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("atlas-db") / "test-dashboard.sqlite3"
    app = create_app(db_path=db_path, data_dir=ROOT / "data", awareness_dir=ROOT / "awareness", seed=True)
    with TestClient(app) as test_client:
        yield test_client
