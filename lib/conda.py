# setting up conda environment, assumes conda is already installed

import subprocess
import re

class Conda:

    def __init__(self, env_name=None, env_file='env.yml'):
        if env_name is None:
            self.env_name = self.name_from_env_file(env_file)
        else:
            self.env_name = env_name
        self.env_file = env_file

    @staticmethod
    def name_from_env_file(env_file):
        # pyyaml is not a standard python library
        # so we have to parse the file the old fashioned way
        # We're looking for "name: <env_name>"
        with open(env_file, 'r') as f:
            for line in f.readlines():
                match = re.match(r'name\: (.*)', line)
                if match:
                    return match.group(1)

    def setup(self):
        # ensure conda is installed
        if not self.conda_installed():
            print('conda not installed. You can install Anaconda from https://www.anaconda.com/download')
            exit(1)

        if not self.env_exists():
            # we need to create the environment first
            self.create_env()
        else: # we need to ensure the environment is up to date
            self.update_env()
        self.activate_env()

    def env_exists(self):
        env_list = subprocess.check_output('conda env list'.split(' '), text=True)
        for line in env_list.split("\n"):
            if re.match(fr'^{self.env_name} ', line):
                return True
        return False

    def conda_installed(self):
        try:
            subprocess.check_call('conda --version'.split(' '))
            return True
        except FileNotFoundError:
            return False

    def create_env(self):
        subprocess.run(f'conda env create -f {self.env_file}'.split(' '))

    def update_env(self):
        subprocess.run(f'conda env update -f {self.env_file}'.split(' '))

    def activate_env(self):
        subprocess.run(f'conda activate {self.env_name}'.split(' '))

    def deactivate_env(self):
        subprocess.run(f'conda deactivate {self.env_name}'.split(' '))
