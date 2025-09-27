from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from dateutil.parser import parse
import json


@dataclass
class RowIp:
    id: int
    blocklist: str
    first_seen: datetime
    ip: str
    other_info: dict


class BaseBlocklistNg:
    def __init__(self, meta, data, created=None):
        self.meta = meta
        self.data = data
        self.created = created
        self.skipped = 0

    def _parse(self, row, id=None) -> RowIp:
        pass

    def parse(self):
        self.skipped = 0
        if self.meta['format'] == 'multiline':
            for idx, row in enumerate(self.data):
                row = remove_comment(row)
                if row is None:
                    self.skipped += 1
                    continue
                parsed = self._parse(row, id=idx-self.skipped)
                if parsed.ip is not None and parsed.first_seen is not None:
                    yield parsed
        elif self.meta['format'] == 'json':
            for idx, row in enumerate(self.data):
                parsed = self._parse(row, id=idx)
                yield parsed


class BlocklistNgParserNixSpam(BaseBlocklistNg):
    def __init__(self, meta, data, created=None):
        super(BlocklistNgParserNixSpam, self).__init__(meta, data, created)

    def _parse(self, row, id=None) -> RowIp:
        items = row.strip().split(" ")
        d = datetime.strptime(items[0], "%Y-%m-%dT%H:%M%z")
        ip = items[1]
        return RowIp(
            ip=ip,
            first_seen=d,
            blocklist=self.meta["source"],
            id=id if id else 0,
            other_info={}
        )


class BlocklistNgParserAposemat(BaseBlocklistNg):
    def __init__(self, meta, data, created=None):
        super(BlocklistNgParserAposemat, self).__init__(meta, data, created)
        if self.created is None:
            self.created = datetime.now()

    def _parse(self, row, id=None) -> RowIp:
        """Number,IP address,Rating"""
        number, ip, rating = row.strip().split(",")
        return RowIp(
            ip=remove_iprange(remove_comment(ip)),
            first_seen=self.created,
            blocklist=self.meta["source"],
            id=number,
            other_info={
                "rating": rating
            }
        )


class BlocklistNgParserAbuseIPDB(BaseBlocklistNg):
    def __init__(self, meta, data, created=None):
        super(BlocklistNgParserAbuseIPDB, self).__init__(meta, data, created)
        data = "\n".join(data)
        self.json_data = json.loads(data)
        self.data = self.json_data["data"]
        self.created = datetime.fromisoformat(self.json_data["meta"]["generatedAt"])

    def _parse(self, row, id=None) -> RowIp:
        return RowIp(
            ip=row["ipAddress"],
            first_seen=None,
            blocklist=self.meta["source"],
            id=id,
            other_info={
                "countryCode": row["countryCode"],
                "abuseConfidenceScore": row["abuseConfidenceScore"],
                "lastReportedAt": datetime.fromisoformat(row["lastReportedAt"])
            }
        )


class BlocklistNgParserAbuseCh(BaseBlocklistNg):
    def __init__(self, meta, data, created=None):
        super(BlocklistNgParserAbuseCh, self).__init__(meta, data, created)

    def _parse(self, row, id=None) -> RowIp:
        """# Firstseen,DstIP,DstPort"""
        items = row.split(",")
        return RowIp(
            ip=str(items[1]).strip(),
            first_seen=datetime.fromisoformat(items[0]),
            blocklist=self.meta["source"],
            id=id,
            other_info={
                "port": int(items[2])
            }
        )


class BlocklistNgParserSingleIpCol(BaseBlocklistNg):
    def __init__(self, meta, data, created=None):
        super(BlocklistNgParserSingleIpCol, self).__init__(meta, data, created)

    def _parse(self, row, id=None) -> RowIp:
        return RowIp(
            ip=str(row).strip(),
            first_seen=self.created,
            blocklist=self.meta["source"],
            id=id,
            other_info={}
        )


class BlocklistNgParserStamparm(BaseBlocklistNg):
    def __init__(self, meta, data, created=None):
        super(BlocklistNgParserStamparm, self).__init__(meta, data, created)

    def _parse(self, row, id=None) -> RowIp:
        """# IP	number of (black)lists"""
        items = row.split()
        return RowIp(
            ip=items[0],
            first_seen=self.created,
            blocklist=self.meta["source"],
            id=id,
            other_info={
                "number_of_blacklists": int(items[1])
            }
        )


class BlocklistNgParserSpamHaus(BaseBlocklistNg):
    def __init__(self, meta, data, created=None):
        super(BlocklistNgParserSpamHaus, self).__init__(meta, data, created)

    def _parse(self, row, id=None) -> RowIp:
        return RowIp(
            ip=remove_iprange(str(row).strip()),
            first_seen=self.created,
            blocklist=self.meta["source"],
            id=id,
            other_info={}
        )


class ParserFactory:
    @classmethod
    def get(cls, meta, data, created=None, parser="AbuseCh") -> Optional[BaseBlocklistNg]:
        parsers = {
            "AbuseCh": BlocklistNgParserAbuseCh,
            "SingleIpColParser": BlocklistNgParserSingleIpCol,
            "AbuseIPDB": BlocklistNgParserAbuseIPDB,
            "SpamHaus": BlocklistNgParserSpamHaus,
            "Aposemat": BlocklistNgParserAposemat,
            "Stamparm": BlocklistNgParserStamparm,
            "NixSpam": BlocklistNgParserNixSpam
        }
        parser = parsers.get(parser)
        if parser:  # if parser exists, then instantiate
            parser = parser(meta, data, created)
        return parser


def remove_comment_gen(lines):
    for line in lines:
        yield remove_comment(line)


def remove_comment(line: str, separators='#;'):
    line = line.strip()
    for sep in separators:
        pos = line.find(sep)
        if pos >= 0:
            line = line[0:pos].strip()
            break
    if line == '':
        return None
    return line


def remove_iprange(line: str):
    return line[0:line.find('/')].strip()


class BlocklistSources:
    def __init__(self, sources_file):
        self.sources_file = sources_file
        self.sources = self.load_blocklist_sources()

    def load_blocklist_sources(self):
        with open(self.sources_file, 'r') as sources_fp:
            sources = json.load(sources_fp)
        return sources

    def all_active(self):
        for source in self.sources:
            if not bool(source.get("disabled", False)):
                yield source

    def search(self, source, tags=None):
        if isinstance(tags, str):
            tags = [tags]
        for source_item in self.sources:
            if source == source_item["source"]:
                if tags is not None:
                    source_tags = source_item["tags"]
                    if len(set(tags).difference(set(source_tags))) == 0:
                        yield source_item
                else:
                    yield source_item

    @staticmethod
    def make_short_blacklist_name(source):
        tags = '-'.join(source['tags'])
        return '_'.join(filter(lambda x: x != '', [source['source'], tags]))

    @staticmethod
    def parse_short_blocklist_name(name):
        res = name.split("_")
        source = res[0]
        if len(res) == 2:
            tags = res[1].split("-")
        else:
            tags = []
        return source, tags
