from datetime import datetime
from dateutil.parser import parse
from jq import jq
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
        self.json_query = '.data'
        self.json_data = json.loads(file_content[0])

    def json(self):
        for idx, row in enumerate(jq(self.json_query).transform(self.json_data)):
            self.row = row
            yield idx, ('asd', row[self.ip_field], self.other_info())


def ParserFactory(parser="AbuseCh"):
    parsers = {
        "AbuseCh": BlackListParserAbuseCh,
        "SingleIpColParser": BlackListParserSingleIpCol,
        "AbuseIPDB": BlackListParserAbuseIPDB,
        "SpamHaus": BlackListParserSpamHaus,
        "Aposemat": BlackListParserAposemat,
        "Stamparm": BlackListParserStamparm
    }
    return parsers[parser]


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
