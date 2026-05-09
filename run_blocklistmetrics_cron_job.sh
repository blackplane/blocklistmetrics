#!/bin/bash

UV=/home/pi/.local/bin/uv

cd blocklistmetrics/ && $UV run python blm.py -c /home/pi/blocklistmetrics/config/cron_blm.json

