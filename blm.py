#!/usr/bin/env python
"""Blacklist Metrics alpha"""

import argparse
import json
import logging

import certifi
import urllib3

from blocklistmetrics.ingest import read_all_blocklists_from
from blocklistmetrics.loader import BlocklistLoader

http = urllib3.PoolManager(
    cert_reqs='CERT_REQUIRED',
    ca_certs=certifi.where()
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(threadName)s %(name)s %(message)s")

config = {
    'config_file': 'config/bm_config.json',
    'output': 'blocklist_data',
    'urls': 'config/blocklist_urls.json'
}


def strip_args(a):
    if a.startswith('--'):
        return a[2:]
    elif a[0] == '<' or a[-1] == '>':
        return a[1:-1]
    return a


def read_config_file_and_replace_with_args(args):
    if args.config:
        config_file = json.load(open(args.config))
    else:
        config_file = {}
    for k in set(config.keys()).intersection(config_file.keys()):
        config[k] = config_file[k]
    if args.config:
        config['config_file'] = args.config
    if args.output:
        config['output'] = args.output
    if args.urls:
        config['urls'] = args.urls
    # positive_args = list(filter(lambda x: x is not None or x, args.keys()))
    # stripped_positive_args = set(map(strip_args, positive_args))
    # for k in set(config.keys()).intersection(set(map(strip_args, stripped_positive_args))):
    #     print(k,config)
    #     config[k] = args[k]
    return config


def parse_args():
    parser = argparse.ArgumentParser()
    # parser.add_argument("-d", "--download",
    #                     help="Download and store blocklists",
    #                     type=str)
    parser.add_argument("-o", "--output",
                        help="Location for the output file",
                        type=str)
    parser.add_argument("-u", "--urls",
                        help="Location for the urls file",
                        type=str)
    parser.add_argument("-c", "--config",
                        help="Config to use",
                        type=str)
    parser.add_argument("-i", "--ingest",
                        help="ingest files from output dir",
                        action="store_true")
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    read_config_file_and_replace_with_args(args=args)
    logging.info(config)
    logging.info('======= Starting Blacklist =======')

    if args.ingest:
        print("ingest", f"{config}")
        for meta, ts, data in read_all_blocklists_from(config["output"], config["urls"]):
            print(meta)
            pass
    else:
        loader = BlocklistLoader(urls_json=config['urls'], destination_path=config['output'])
        loader.run()

    logging.info('========== Wrapping up ===========')


if __name__ == '__main__':
    main()
