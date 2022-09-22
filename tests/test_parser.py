from blocklistmetrics.parser import BlocklistSources
import pytest


def test_sources_search_multiple(blocklist_sources):
    res = [x for x in blocklist_sources.search("blocklist.de")]
    assert len(res) > 1, "Not enough sources"


def test_sources_search_single(blocklist_sources):
    res = [x for x in blocklist_sources.search("blocklist.de", "all")]
    assert len(res) == 1, "Source not found"


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
