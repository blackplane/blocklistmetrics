from dataclasses import dataclass
from datetime import datetime
from dateutil.parser import parse
import json
#
# BlacklistName, Firstseen, IP, OtherInfo
#
# Firstseen, DstIP, DstPort, LastOnline, Malware
# Firstseen,DstIP,DstPort,Malware
# Firstseen,DstIP,DstPort
# ipAddress abuseConfidenceScore lastReportedAt
# ip, country, city, longitude, latitude
#


class BaseBlacklist:
    def __init__(self):
        self.row = None
        self.ip_field = 'ip'
        self.first_seen_field = 'first_seen_field'

    def first_seen(self):
        if self.row:
            return self.row[self.first_seen_field]
        else:
            return None

    def ip(self):
        if self.row:
            return self.row[self.ip_field]
        else:
            return None

    def other_info(self):
        if self.row:
            return {k: self.row[k] for k in self.row.keys() - {self.ip_field, self.first_seen_field}}
        else:
            return None




class BlackListParserAbuseCh(BaseBlacklist):
    def __init__(self, line, desc, sep=','):
        super(BlackListParserAbuseCh, self).__init__()
        fields = desc['fields']
        self.first_seen_field = desc['firstseen']
        self.ip_field = desc['ip']
        self.row = {}
        if line is not None:
            self.row = dict(zip(fields, line.split(sep)))
        else:
            self.row = None


class BlackListParserSingleIpCol(BaseBlacklist):
    def __init__(self, line, desc):
        super(BlackListParserSingleIpCol, self).__init__()
        if 'first_seen' not in desc.keys():
            desc[self.first_seen_field] = datetime.now().strftime('%Y-%m-%d')
        self.row = {self.ip_field: remove_comment(line),
                    self.first_seen_field: desc[self.first_seen_field]}


class BlackListParserSpamHaus(BaseBlacklist):
    def __init__(self, line, desc):
        super(BlackListParserSpamHaus, self).__init__()
        if 'first_seen' not in desc.keys():
            desc[self.first_seen_field] = datetime.now().strftime('%Y-%m-%d')
        timestamp_str, line = line.split(' ')
        self.row = {self.ip_field: remove_iprange(remove_comment(line)),
                    self.first_seen_field: parse(timestamp_str)}


class BlackListParserStamparm(BaseBlacklist):
    def __init__(self, line, desc):
        super(BlackListParserStamparm, self).__init__()
        if 'first_seen' not in desc.keys():
            desc[self.first_seen_field] = datetime.now().strftime('%Y-%m-%d')
        l = line.split()
        ip_field, occurrence = line.split() # Number,IP address,Rating
        self.row = {self.ip_field: remove_iprange(remove_comment(ip_field)),
                    self.first_seen_field: desc[self.first_seen_field],
                    'occurrence': occurrence}


class BlackListParserAposemat(BaseBlacklist):
    def __init__(self, line, desc):
        super(BlackListParserAposemat, self).__init__()
        if 'first_seen' not in desc.keys():
            desc[self.first_seen_field] = datetime.now().strftime('%Y-%m-%d')
        _, ip_field, rating = line.split(',') # Number,IP address,Rating
        self.row = {self.ip_field: remove_iprange(remove_comment(ip_field)),
                    self.first_seen_field: desc[self.first_seen_field],
                    'rating': rating}


class BlackListParserAbuseIPDB(BaseBlacklist):
    def __init__(self, file_content, desc):
        super(BlackListParserAbuseIPDB, self).__init__()
        self.ip_field = 'ipAddress'
        self.first_seen_field = None
        self.json_data = json.loads(file_content[0])

    def json(self):
        for idx, row in enumerate(self.json_data["data"]):
            self.row = row
            yield idx, ('asd', row[self.ip_field], self.other_info())



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

    def _parse(self, line, id=None) -> RowIp:
        pass

    def parse(self):
        skipped = 0
        if self.meta['format'] == 'multiline':
            for idx, line in enumerate(self.data):
                line = remove_comment(line)
                if line is None:
                    skipped += 1
                    continue
                parsed = self._parse(line, id=idx)
                if parsed.ip is not None and parsed.first_seen is not None:
                    yield parsed
        elif self.meta['format'] == 'json':
            parsed = self._parse(self.data)
            for row in parsed.json():
                yield row


class BlocklistNgParserNixSpam(BaseBlocklistNg):
    def __init__(self, meta, data, created=None):
        super(BlocklistNgParserNixSpam, self).__init__(meta, data, created)

    def _parse(self, line, id=None) -> RowIp:
        items = line.strip().split(" ")
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

    def _parse(self, line, id=None) -> RowIp:
        """Number,IP address,Rating"""
        number, ip, rating = line.strip().split(",")
        return RowIp(
            ip=remove_iprange(remove_comment(ip)),
            first_seen=self.created,
            blocklist=self.meta["source"],
            id=number,
            other_info={
                "rating": rating
            }
        )


class ParserFactory:
    @classmethod
    def get(cls, meta, data, created=None, parser="AbuseCh"):
        parsers = {
            "AbuseCh": None,
            "SingleIpColParser": None,
            "AbuseIPDB": None,
            "SpamHaus": None,
            "Aposemat": BlocklistNgParserAposemat,
            "Stamparm": None,
            "NixSpam": BlocklistNgParserNixSpam
        }
        return parsers[parser](meta, data, created)


def remove_comment_gen(lines):
    for line in lines:
        yield remove_comment(line)


def remove_comment(line: str, separators='#;'):
    for sep in separators:
        pos = line.find(sep)
        if pos >= 0:
            line = line[0:pos].strip()
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
