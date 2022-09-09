from blocklistmetrics.parser import ParserFactory
from blocklistmetrics.parser import remove_comment


def ingest(desc, file_content):
    blacklist_name = desc['name']
    parser = ParserFactory(desc['parser'])
    res = {}
    skipped = 0

    if desc['format'] == 'multiline':
        for idx, line in enumerate(file_content):
            line = remove_comment(line)
            if line is None:
                skipped += 1
                continue
            parsed = parser(line, desc)
            if parsed.ip() is not None and parsed.first_seen() is not None:
                res[idx] = {'idx': idx,
                            'BlacklistName': blacklist_name,
                            'FirstSeen': parsed.first_seen(),
                            'IP': parsed.ip(),
                            'OtherInfo': parsed.other_info()}
    elif desc['format'] == 'json':
        parsed = parser(file_content, desc)
        for idx, (first_seen, ip, other_info) in parsed.json():
            res[idx] = {'idx': idx,
                        'BlacklistName': blacklist_name,
                        'FirstSeen': first_seen,
                        'IP': ip,
                        'OtherInfo': other_info}

    return res, skipped
#
#
# def ingest_csv(desc, file_content):
#     blacklist_name = desc['name']
#     parser = ParserFactory(desc['parser'])
#     res = {}
#     for idx, line in enumerate(remove_comment_gen(file_content)):
#         parsed = parser(line, desc)
#         if parsed.ip() is not None and parsed.first_seen() is not None:
#             res[idx] = {'idx': idx,
#                         'BlacklistName': blacklist_name,
#                         'FirstSeen': parsed.first_seen(),
#                         'IP': parsed.ip(),
#                         'OtherInfo': parsed.other_info()}
#     return res
