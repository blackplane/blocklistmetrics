import gzip
import os
from datetime import datetime

import pytest

from blocklistmetrics.parser import BlocklistSources


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
def nixspam(data_path, blocklist_sources):
    with gzip.open(os.path.join(data_path, "nixspam_spam")) as fp:
        c = fp.readlines()
        data = list(map(lambda x: x.decode("utf-8").strip(), c))
    blocklist_load_date = datetime.now()
    meta = [x for x in blocklist_sources.search("nixspam", "spam")]
    return meta[0], blocklist_load_date, data


@pytest.fixture
def aposemat(data_path, blocklist_sources):
    with open(os.path.join(data_path, "aposemat_aip")) as fp:
        data = fp.readlines()
    blocklist_load_date = datetime.now()
    meta = [x for x in blocklist_sources.search("aposemat", "aip")]
    return meta[0], blocklist_load_date, data


@pytest.fixture
def abuseipdb(data_path, blocklist_sources):
    with open(os.path.join(data_path, "AbuseIPDB_blacklist")) as fp:
        data = fp.readlines()
    blocklist_load_date = datetime.now()
    meta = [x for x in blocklist_sources.search("AbuseIPDB", "blacklist")]
    return meta[0], blocklist_load_date, data


@pytest.fixture
def abusech(data_path, blocklist_sources):
    with open(os.path.join(data_path, "abuse.ch_sslbl-botnet")) as fp:
        data = fp.readlines()
    blocklist_load_date = datetime.now()
    meta = [x for x in blocklist_sources.search("abuse.ch", ["sslbl", "botnet"])]
    return meta[0], blocklist_load_date, data


@pytest.fixture
def emergingthreats(data_path, blocklist_sources):
    with open(os.path.join(data_path, "emergingthreats_fwrules")) as fp:
        data = fp.readlines()
    blocklist_load_date = datetime.now()
    meta = [x for x in blocklist_sources.search("emergingthreats", "fwrules")]
    return meta[0], blocklist_load_date, data


@pytest.fixture
def spamhaus(data_path, blocklist_sources):
    with open(os.path.join(data_path, "spamhaus.org_DROPList-spam")) as fp:
        data = fp.readlines()
    blocklist_load_date = datetime.now()
    meta = [x for x in blocklist_sources.search("spamhaus.org", ["DROPList", "spam"])]
    return meta[0], blocklist_load_date, data


@pytest.fixture
def stamparm(data_path, blocklist_sources):
    with open(os.path.join(data_path, "stamparm_ipsum")) as fp:
        data = fp.readlines()
    blocklist_load_date = datetime.now()
    meta = [x for x in blocklist_sources.search("stamparm", "ipsum")]
    return meta[0], blocklist_load_date, data
