import json
import os
import logging
import requests
import gzip
import certifi
from datetime import datetime


def make_short_blacklist_name(source):
    return source['source'] + '_' + '-'.join(source['tags'])


def download_file(url, path, headers=None, verify=False):
    if headers is not None:
        file = requests.get(url, headers=headers, verify=verify)
    else:
        file = requests.get(url, verify=False)
    file_content = post_process(file, url)
    return file_content


def download_and_save_file(url, path, headers=None, verify=None):
    file_content = download_file(url, path, headers, verify)
    if file_content is not None:
        try:
            open(path, 'wb').write(file_content)
            logging.info(f"Written blocklist to {path}")
        except Exception as ex:
            logging.error(f"url={url}\nexception={ex}")


def post_process(file, url):
    file_content = None
    if url.endswith('.gz'):
        try:
            file_content = gzip.decompress(file.content)
        except Exception as ex:
            logging.error(f"url={url}\nexception={ex}")
    if file.content is not None:
        file_content = file.content
    return file_content


def create_path_if_not_exists(path):
    if isinstance(path, list):
        path = os.path.join(path)
    os.makedirs(path, mode=0o755, exist_ok=True)


def idx_str(idx):
    if idx != 0:
        return str(idx)
    return ''


class BlocklistLoader:
    def __init__(self, urls_json, destination_path='.'):
        self.destination_path = destination_path
        with open(urls_json, 'r') as urls_json_fp:
            self.sources = json.load(urls_json_fp)

    def run(self):
        d = datetime.now()
        destination_path_current = os.path.join(self.destination_path, d.strftime("%Y-%m-%d_%H-%M"))
        create_path_if_not_exists(destination_path_current)
        for source in self.sources:
            short_blacklist_name = make_short_blacklist_name(source)
            logging.info(f"""Downloading blacklist {short_blacklist_name}""")
            for idx, url in enumerate(source['list_url']):
                if 'headers' in source:
                    headers = source['headers']
                else:
                    headers = None
                path = os.path.join(destination_path_current, ''.join([short_blacklist_name, idx_str(idx)]))
                download_and_save_file(url, path, headers=headers, verify=certifi.where())
