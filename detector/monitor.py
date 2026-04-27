#!/usr/bin/env python3

import json
import os
import time
def monitor_logs(logpath):
    """
    Monitor te log file for new entries and process them.
    """
    while not os.path.exists(logpath):
        print(f"Waiting for log file {logpath} to be created...")
        time.sleep(1)

    with open(logpath, 'r') as file:
        #  Move the cursor to read from the end of the file, to always read new entries
        file.seek(0, 2)
        while True:
            line = file.readline()
            if line:
                try:
                    log_data = json.loads(line)
                    yield log_data
                except json.JSONDecodeError:
                    continue
            else:
                time.sleep(0.1)