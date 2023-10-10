import os
from lib.conda import Conda

AZUREML_CONFIG_FILE = os.path.join('config', 'azureml_config.json')
DEFAULT_WORKSPACE = 'dt-datascience-core-dev-usw2'
DEFAULT_RESOURCE_GROUP = 'dt-datascience-core-dev-usw2'
DEFAULT_VM_SIZE = 'Standard_DS12_v2'
VALID_VM_SIZES = ['Standard_DS11_v2', 'Standard_DS3_v2', 'Standard_DS12_v2', 'Standard_D13_v2']
DEFAULT_SUBSCRIPTION_ID = 'a1eab4f0-e17c-4e70-ab04-833c063dc515'
DEFAULT_SSH_USER = 'azureuser'
SSH_PORT = 50001
SSH_DIR = os.path.expanduser('~') + '/.ssh'
SSH_KNOWN_HOSTS = os.path.join(SSH_DIR, 'known_hosts')
EXE_NAME = Conda.name_from_env_file('env.yml')
