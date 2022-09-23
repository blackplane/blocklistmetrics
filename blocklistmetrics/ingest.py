import os
import logging
import gzip
from datetime import datetime
from blocklistmetrics.parser import ParserFactory, BlocklistSources
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


def list_all_blocklist_dirs(destination_path, sources_file):
    def is_blocklist(file):
        return True
    try:
        (root, dirs, files) = next(os.walk(destination_path))
        assert len(files) > 0, f"Blocklist directory {destination_path} seems to be empty"
        return [os.path.join(root, file) for file in files if is_blocklist(file)]
    except StopIteration as ex:
        logging.error(f"StopIteration exception when reading blocklist files, maybe {destination_path} does not exist")
        return
    except AssertionError as ex:
        logging.warning(ex)


def read_all_blocklists_from(destination_path, sources_file):
    def flatten(list_of_lists):
        return [item for sublist in list_of_lists for item in sublist]

    def to_datetime(s):
        try:
            return datetime.strptime(s, "%Y-%m-%d_%H-%M")
        except ValueError:
            return None

    def read_binary(path):
        with gzip.open(path) as fp:
            return list(map(lambda x: x.decode("utf-8").strip(), fp.readlines()))

    sources = BlocklistSources(sources_file)
    try:
        (root, dirs, files) = next(os.walk(destination_path))
        blocklist_files = flatten([
            list_all_blocklist_dirs(os.path.join(destination_path, d), sources_file)
            for d in dirs
        ])
        for blocklist_file in blocklist_files:
            p = blocklist_file.split("/")
            blocklist_load_date = to_datetime(p[-2])
            blocklist_file_name = p[-1]
            source, tags = BlocklistSources.parse_short_blocklist_name(blocklist_file_name)
            meta = list(sources.search(source, tags))[0]
            try:
                with open(blocklist_file, "r") as fp:
                    data = fp.readlines()
            except UnicodeDecodeError:
                data = read_binary(blocklist_file)
            yield meta, blocklist_load_date, data
    except StopIteration as ex:
        logging.error(f"StopIteration exception when reading blocklist files, maybe {destination_path} does not exist")
        return
    except AssertionError as ex:
        logging.warning(ex)
