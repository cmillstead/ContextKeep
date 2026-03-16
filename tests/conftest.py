import pytest
from core.memory_manager import MemoryManager


@pytest.fixture
def manager(tmp_path):
    """Create a MemoryManager with a temp data directory."""
    data_dir = tmp_path / "data" / "memories"
    data_dir.mkdir(parents=True)
    mgr = MemoryManager()
    mgr.cache_dir = data_dir
    return mgr
