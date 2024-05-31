import os, re
from docopt import docopt
from src.mlvm import Mlvm
from src import const

def version():
    changelog_txt = open("CHANGELOG.md").read()
    version = re.findall(r"\[\d.*\].*", changelog_txt)[0]
    return f"Azure ML VM CLI version {version}"

def default_arg_str(arg, mlvm):
    config_arg = mlvm.azureml_config.get(arg)
    if config_arg:
        return f" [default: {config_arg}]"
    return f" If not set, you will be prompted to enter a {re.sub('_', ' ', arg)}."


mlvm = Mlvm()

# Help message per doctopt requirements
msg = f"""Azure ML VM CLI

Usage:
    mlvm setup [--workspace WORKSPACE_NAME] [--resource-group RESOURCE_GROUP] [--subscription-id SUBSCRIPTION_ID]
               [--vm-name VM_NAME] [--vm-size VM_SIZE] [--ssh-user SSH_USER] [--ssh-public-key-file FILE_PATH]
               [--ssh-private-key-file FILE_PATH] [--verbose]
    mlvm update [--verbose]
    mlvm start [(-w, --wait)] [--verbose]
    mlvm stop [(-w, --wait)] [--verbose]
    mlvm ssh [--verbose]
    mlvm (-h | --help)
    mlvm --version

Options:
    -h --help                         Show this screen
    --version                         Display the current version of this CLI
    --verbose                         Show more text
    --workspace WORKSPACE_NAME        Name of your Azure ML workspace [default: {mlvm.azureml_config.get('workspace') or const.DEFAULT_WORKSPACE}]
    --resource-group RESOURCE_GROUP   Name of your Azure ML resource group [default: {mlvm.azureml_config.get('resource_group') or const.DEFAULT_RESOURCE_GROUP}]
    --subscription-id SUBSCRIPTION_ID Your Azure ML subscription ID [default: {mlvm.azureml_config.get('subscription_id') or const.DEFAULT_SUBSCRIPTION_ID}]
    --vm-name VM_NAME                 Recommended format: ds-vm-<yourname>{default_arg_str('vm_name', mlvm)}
    --vm-size VM_SIZE                 Size/Type of your Azure ML Compute Instance [default: {mlvm.azureml_config.get('vm_size') or const.DEFAULT_VM_SIZE}]
    --ssh-user SSH_USER               Admin username for the Compute Instance [default: {mlvm.azureml_config.get('ssh_user') or const.DEFAULT_SSH_USER}]
    --ssh-public-key-file FILE_PATH   Path to your SSH public key file [default: {mlvm.azureml_config.get('ssh_public_key_file') or os.path.join(const.SSH_DIR,'id_rsa.pub')}
    --ssh-private-key-file FILE_PATH  Path to your SSH private key file [default: {mlvm.azureml_config.get('ssh_private_key_file') or os.path.join(const.SSH_DIR,'id_rsa')}]
    -w --wait                         Wait for the request (stop/start Compute Instance) to be completed
"""

args = docopt(msg, version=version())
args['--wait'] = bool(args) # docopt sets these to 0 or 1, needs to be bool

if args['setup']:
    mlvm.setup(args['--workspace'], args['--resource-group'], args['--subscription-id'],
               args['--vm-name'], args['--vm-size'], args['--ssh-user'],
               args['--ssh-public-key-file'], args['--ssh-private-key-file'])
elif args['update']:
    mlvm.update()
elif args['start']:
    mlvm.start(args['--wait'])
elif args['stop']:
    mlvm.stop(args['--wait'])
elif args['ssh']:
    mlvm.ssh()
