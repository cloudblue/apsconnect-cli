from __future__ import print_function

import json
import os
import sys

CFG_FILE_PATH = os.path.expanduser('~/.apsconnect/.aps_config')
NULL_CFG_INFO = (None, None)


def get_config():
    try:
        with open(CFG_FILE_PATH) as f:
            cfg = json.load(f)
    except IOError as e:
        if e.errno == 2:
            print("Could not find connected hub data. "
                  "Please run the init-hub command to connect Odin Automation hub.")
        else:
            print("Could not open configuration file:\n{}".format(e))
        sys.exit(1)
    except ValueError:
        print("Could not parse the configuration file, please re-run "
              "the init-hub command to regenerate the configuration.")
        sys.exit(1)
    except Exception as e:
        print("Failed to read connected hub configuration. Error message:\n{}".format(e))
        sys.exit(1)
    else:
        return cfg
