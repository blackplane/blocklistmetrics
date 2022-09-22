import pytest
import os
from blocklistmetrics.parser import BlocklistSources


@pytest.fixture
def blocklist_urls_path(request):
    rootpath = os.path.join(request.fspath.dirname, '..')
    return os.path.join(rootpath, "config", "blocklist_urls.json")


@pytest.fixture
def blocklist_sources(blocklist_urls_path):
    return BlocklistSources(blocklist_urls_path)