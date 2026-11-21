import pytest

from agentwatch.config import Config
from agentwatch.store import Store


@pytest.fixture
def store():
    return Store(":memory:")


@pytest.fixture
def cfg():
    return Config(networks=["192.168.1.0/24"], db_path=":memory:")
