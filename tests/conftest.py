import pytest
import os
from blocklistmetrics.parser import BlocklistSources
import gzip


@pytest.fixture
def data_path(request):
    return os.path.join(request.fspath.dirname, 'data')


@pytest.fixture
def blocklist_urls_path(request):
    rootpath = os.path.join(request.fspath.dirname, '..')
    return os.path.join(rootpath, "config", "blocklist_urls.json")


@pytest.fixture
def blocklist_sources(blocklist_urls_path):
    return BlocklistSources(blocklist_urls_path)


@pytest.fixture
def nixspam(data_path):
    with gzip.open(os.path.join(data_path, "nixspam_spam")) as fp:
        c = fp.readlines()
        return list(map(lambda x: x.decode("utf-8").strip(), c))

