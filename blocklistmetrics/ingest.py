import os
from blocklistmetrics.parser import ParserFactory, load_blocklist_sources, BlocklistSources
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



def read_all_blocklists_from(destination_path, sources):
    sources = load_blocklist_sources(sources)
    (_, _, blocklist_files) = next(os.walk(destination_path))
    for blocklist_file in blocklist_files:
        source, tags = BlocklistSources.parse_short_blocklist_name(blocklist_file)
