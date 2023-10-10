#!/usr/bin/env -S conda run --no-capture-output -n mlvm python

import fire
from src.cli import Cli

if __name__ == '__main__':
    fire.Fire(Cli)
