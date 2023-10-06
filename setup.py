#!/usr/bin/env python

import sys
import os
from lib.conda import Conda

# setup conda env
# we have to have our env set up before we import anything else
Conda().setup()
os.system('conda run --no-capture-output -n mlvm python main.py setup ' + ' '.join(sys.argv[1:])) # sys.argv[0] is setup.py
