#!/usr/bin/env python

import sys
from lib.conda import Conda
from main import main

# setup conda env
Conda().setup()

# make sure we run main.py with the first argument of 'setup'
sys.argv.insert(1, 'setup')
main()
