from blocklistmetrics.parser import BlocklistSources, ParserFactory
from blocklistmetrics.ingest import ingest
import pytest


def test_sources_search_multiple(blocklist_sources):
    res = [x for x in blocklist_sources.search("blocklist.de")]
    assert len(res) > 1, "Not enough sources"


def test_sources_search_single(blocklist_sources):
    res = [x for x in blocklist_sources.search("blocklist.de", "all")]
    assert len(res) == 1, "Source not found"


def test_binary_parser(blocklist_sources, nixspam):
    meta, created, data = nixspam
    assert len(meta.keys()) >= 6, "Source not found"
    parser = ParserFactory.get(meta, data, created, parser="NixSpam")
    assert parser is not None
    parser = ParserFactory.get(meta, data, created, parser="ParserThatDontExist")
    assert parser is None


def test_parse_nixspam(nixspam):
    meta, created, data = nixspam
    parser = ParserFactory.get(meta, data, created, parser="NixSpam")
    res = list(parser.parse())
    assert len(res) > 0


def test_parse_aposemat(aposemat):
    meta, created, data = aposemat
    parser = ParserFactory.get(meta, data, created, parser="Aposemat")
    res = list(parser.parse())
    assert len(res) > 0


def test_parse_abuseipdb(abuseipdb):
    meta, created, data = abuseipdb
    parser = ParserFactory.get(meta, data, created, parser="AbuseIPDB")
    res = list(parser.parse())
    assert len(res) > 0


def test_parse_abusech(abusech):
    meta, created, data = abusech
    parser = ParserFactory.get(meta, data, created, parser="AbuseCh")
    res = list(parser.parse())
    assert len(res) > 0


def test_parse_emergingthreats(emergingthreats):
    meta, created, data = emergingthreats
    parser = ParserFactory.get(meta, data, created, parser="SingleIpColParser")
    res = list(parser.parse())
    assert len(res) > 0


def test_parse_stamparm(stamparm):
    meta, created, data = stamparm
    parser = ParserFactory.get(meta, data, created, parser="Stamparm")
    res = list(parser.parse())
    assert len(res) > 0


def test_parse_spamhaus(spamhaus):
    meta, created, data = spamhaus
    parser = ParserFactory.get(meta, data, created, parser="SpamHaus")
    res = list(parser.parse())
    assert len(res) > 0

#
# def test_ingest(blocklist_sources, nixspam):
#     meta, blocklist_load_date, data = nixspam
#     res = ingest(meta, data)
#     pass


@pytest.mark.parametrize(
    "test_source, result",
    [
        ({"source": "myblocklist", "tags": ["tag", "along"]}, True),
        ({"source": "notags", "tags": []}, True),
    ],
)
def test_short_names(test_source, result):
    short_name = BlocklistSources.make_short_blacklist_name(test_source)
    source, tags = BlocklistSources.parse_short_blocklist_name(short_name)
    assert test_source["source"] == source and test_source["tags"] == tags, "Conversion didn't match"
