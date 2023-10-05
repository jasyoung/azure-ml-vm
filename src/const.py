import os
from lib.conda import Conda

AZUREML_CONFIG_FILE = 'config/azureml_config.json'
DEFAULT_WORKSPACE = 'dt-datascience-core-dev-usw2'
DEFAULT_RESOURCE_GROUP = 'dt-datascience-core-dev-usw2'
DEFAULT_VM_SIZE = 'Standard_DS12_v2'
DEFAULT_SUBSCRIPTION_ID = 'a1eab4f0-e17c-4e70-ab04-833c063dc515'
DEFAULT_SSH_USER = 'azureuser'
SSH_DIR = os.path.expanduser('~') + '/.ssh'
EXE_NAME = Conda.name_from_env_file()
