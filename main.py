#!/usr/bin/env python

import click
import re
import os
import subprocess
import json
from cryptography.hazmat import primitives as crypto
import paramiko
import git
from src import const
from lib import log
from lib.conda import Conda
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.ai.ml import MLClient
from azure.ai.ml.entities import ComputeInstance, ComputeInstanceSshSettings

@click.group()
def cli():
    pass

## CLI COMMANDS

@click.command(help='Display the current version of this CLI')
def version():
    changelog_txt = open("CHANGELOG.md").read()
    version = re.findall(r"\[\d.*\].*", changelog_txt)[0]
    click.echo(f"Azure ML VM CLI version {version}")

@click.command(help="Create/Link your VM and set up this CLI to your path")
@click.option('--workspace', default=const.DEFAULT_WORKSPACE)
@click.option('--resource-group', default=None)
@click.option('--subscription-id', default=None)
@click.option('--vm-size', default=const.DEFAULT_VM_SIZE)
@click.option('--ssh-user', default=const.DEFAULT_SSH_USER)
@click.option('--ssh-public-key-file', default=os.path.join(const.SSH_DIR,'id_rsa.pub'))
@click.option('--ssh-private-key-file', default=os.path.join(const.SSH_DIR,'id_rsa'))
def setup(workspace, resource_group, subscription_id, vm_size, ssh_user, ssh_public_key_file, ssh_private_key_file):
    resource_group, subscription_id = set_ml_env_vars(resource_group, subscription_id)
    # configure_azure_credentials()
    ml_client = get_ml_client({'workspace_name': workspace, 'resource_group': resource_group, 'subscription_id': subscription_id})
    vm_linked = link_vm(ml_client, vm_size) # returns a ComputeInstance object, else returns False
    if not vm_linked:
        log.error("Didn't link VM. Setup aborted.")
    setup_ssh(ml_client, vm_linked, ssh_user, ssh_public_key_file, ssh_private_key_file)
    setup_cli(const.EXE_NAME) # create the cli executable add it to PATH
    setup_sf_connection()

@click.command(help="Pull the latest mlvm version, update the conda env, and generate new executable")
def update():
    git.cmd.Git(os.path.dirname(__file__)).pull()
    Conda().update_env()
    setup_cli(const.EXE_NAME)

@click.command(help='Start up your Azure ML VM')
@click.option('-w', '--wait', default=False, help='Wait for the VM to become available')
def start(wait):
    azureml_config = load_azureml_config()
    ml_client = get_ml_client(azureml_config)
    poller = ml_client.compute.begin_start(azureml_config['vm_name'])
    if wait:
        poller.wait()

@click.command(help='Shut down your Azure ML VM')
@click.option('-w', '--wait', default=False, help='Wait for the VM to shut down')
def stop(wait):
    azureml_config = load_azureml_config()
    ml_client = get_ml_client(azureml_config)
    poller = ml_client.compute.begin_stop(azureml_config['vm_name'])
    if wait:
        poller.wait()

@click.command(help='SSH into your Azure ML VM')
def ssh():
    azureml_config = load_azureml_config()
    ssh_client = paramiko.SSHClient()
    ssh_client.look_for_keys(True)
    ssh_client.connect(azureml_config['vm_public_ip'], port=50001, username=azureml_config['ssh_user'])
    ssh_client.close()


## NON COMMANDS

# try to use the passed var first
# if that's not set then try the os.environ
# else use the value in const.py and set to os.environ
def set_ml_env_vars(resource_group, subscription_id):
    if resource_group is None:
        resource_group = set_environ_var('RESOURCE_GROUP_NAME', const.DEFAULT_RESOURCE_GROUP)
    if subscription_id is None:
        subscription_id = set_environ_var('AZURE_SUBSCRIPTION_ID', const.DEFAULT_SUBSCRIPTION_ID)
    return resource_group, subscription_id

def set_environ_var(environ_var, default):
    try:
        return os.environ[environ_var]
    except KeyError:
        os.environ[environ_var] = default
        return default

# azureml_config should be a dict with keys workspace_name, resource_group, and subscription_id
def get_ml_client(azureml_config=None):
    if azureml_config is None:
        azureml_config = load_azureml_config()
    credential = authenticate()
    try:
        ml_client = MLClient.from_config(credential=credential)
    except Exception as ex:
        config_path = const.AZUREML_CONFIG_FILE
        with open(config_path, "w") as fo:
            fo.write(json.dumps(azureml_config))
        ml_client = MLClient.from_config(credential=credential, path=config_path)

    return ml_client

def authenticate():
    log.info("Authenticating...")
    try:
        credential = DefaultAzureCredential()
        # Check if given credential can get token successfully.
        credential.get_token("https://management.azure.com/.default")
    except Exception as ex:
        # Fall back to InteractiveBrowserCredential in case DefaultAzureCredential not work
        # This will open a browser page for
        credential = InteractiveBrowserCredential()
    return credential

def link_vm(ml_client, vm_size):
    vm_name = log.usr_in("Enter name for your vm. Recommended format: ds-vm-<yourname> :")
    vm_provisioned = provision_vm(ml_client, vm_name, vm_size) # provision vm if doesn't exist
    if not vm_provisioned:
        log.warn("Did not provision VM")
        return False
    add_item_to_azureml_config('vm_name', vm_name)
    return vm_provisioned # returns a ComputeInstance object, else returns False

def provision_vm(ml_client, vm_name, vm_size):
    try:
        my_vm = ml_client.compute.get(vm_name)
        log.info(f'Found existing VM {vm_name} in {ml_client.workspace_name}')
        log.info(f'If this is yours, feel free to continue with setup to link it.')
        yn = log.yn('Would you like to continue?')
        if yn:
            return my_vm
        else:
            return False
    except ResourceNotFoundError:
        yn = log.yn(f'Could not find existing VM {vm_name}. Create?')
        if not yn:
            return False
        log.info(f'Provisioning VM {vm_name}. This may take a few minutes.')
        my_vm = ComputeInstance(name=vm_name, size=vm_size, ssh_public_access_enabled=True,
                                idle_time_before_shutdown_minutes=60, setup_scripts=None, enable_node_public_ip=True)
        my_vm = ml_client.compute.begin_create_or_update(my_vm).result()
        return my_vm

def add_item_to_azureml_config(key, value):
    azureml_config = load_azureml_config()
    azureml_config[key] = value
    with open(const.AZUREML_CONFIG_FILE, 'w') as file:
        file.write(json.dumps(azureml_config))
    return value

def load_azureml_config():
    with open(const.AZUREML_CONFIG_FILE, 'r') as azureml_config:
        return json.load(azureml_config)

def setup_ssh(ml_client, compute_instance, ssh_user, public_key_file, private_key_file):
    # save new/existing ssh key file paths in azureml_config
    link_ssh_keypair(public_key_file, private_key_file)

    # update the compute instance with ssh settings
    public_key = load_public_ssh_key()
    ssh_settings = ComputeInstanceSshSettings(public_key, ssh_port=50001)
    compute_instance.ssh_settings = ssh_settings
    compute_instance = ml_client.compute.begin_create_or_update(compute_instance).result()
    add_item_to_azureml_config('vm_public_ip', compute_instance.network_settings.public_ip_address)
    add_item_to_azureml_config('ssh_user', ssh_user)

def link_ssh_keypair(public_key_file, private_key_file):
    if not os.path.isfile(public_key_file):
        log.warn(f'Could not find existing public key file {public_key_file}.')
        if log.yn(f'Generate new ssh keypair with private key at {private_key_file} and public key at {public_key_file}?'):
            # generate a new ssh keypair if we don't have one
            # Assumes we don't have one if the specified public_key_file doesn't exist
            generate_ssh_keypair(private_key_file, public_key_file)
        else:
            log.error("""Did not link ssh keypair. To link an ssh keypair, 
                      please specify the file locations for existing ones, use the default locations, or generate new keys.
                      You can specify specific key locations with the --ssh-public-key-file and --ssh-private-key-file options.
                      Aborting.""")
    else: # assumes we already have an ssh keypair
        # so we just need to note them in the azureml config
        add_item_to_azureml_config('private_ssh_key_file', private_key_file)
        add_item_to_azureml_config('public_ssh_key_file', public_key_file)

def generate_ssh_keypair(private_key_file, public_key_file):
    private_key = crypto.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    if not os.path.exists(const.SSH_DIR):
        os.makedirs(const.SSH_DIR)
    save_private_ssh_key(private_key, private_key_file)
    save_public_ssh_key(public_key, public_key_file)

def save_private_ssh_key(private_key, private_key_file):
    private_pem = private_key.private_bytes(
        encoding=crypto.serialization.Encoding.PEM,
        format=crypto.serialization.PrivateFormat.PKCS8,
        encryption_algorithm=crypto.serialization.NoEncryption()
    )
    file_loc = add_item_to_azureml_config('private_ssh_key_file', private_key_file)
    with open(file_loc, 'wb') as f:
        f.write(private_pem)

def save_public_ssh_key(public_key, public_key_file):
    public_pem = public_key.public_bytes(
        encoding=crypto.serialization.Encoding.PEM,
        format=crypto.serialization.PublicFormat.SubjectPublicKeyInfo
    )
    file_loc = add_item_to_azureml_config('public_ssh_key_file', public_key_file)
    with open(file_loc, 'wb') as f:
        f.write(public_pem)

def load_public_ssh_key():
    public_key_file = load_azureml_config()['public_ssh_key_file']
    with open(public_key_file, "rb") as key_file:
        return crypto.serialization.load_pem_public_key(
            key_file.read()
        )
    
def setup_cli(exe_name):
    PyInstaller.__main__.run(['main.py', '--clean', '--name', exe_name]) # generate the executable
    # path to the newly generated executable (src)
    path_to_exe = os.path.join(os.path.dirname(__file__), 'dist', exe_name, exe_name)
    if os.name == 'nt': # Windows
        path_to_exe += '.exe'
    # path to the soft link (dst)
    linked_file = select_loc_for_linked_file(exe_name)
    # Assuming the linked file is in your PATH, this cli will be callable as mlvm
    os.symlink(path_to_exe, linked_file)

def select_loc_for_linked_file(exe_name):
    # select the env dir that contains the exe_name, which is assumed to be the same as the env_name
    env_dirs = json.loads(subprocess.check_output('conda env list -v --json'.split(' '), text=True))
    for env_dir in env_dirs['envs']:
        if env_dir.endswith(exe_name):
            return os.path.join(env_dir, exe_name)
    log.error('Could not find conda env mlvm. Please find the mlvm executable and link it to your PATH manually.')

def setup_sf_connection():
    pass

# We shouldn't need to use this since it should be taken care of
# If it turns out we don't need it, remove subprocess import and azure-cli dependency
def ensure_logged_in():
    subprocess.run('az login --use-device-code'.split(' '))

## ADD COMMANDS TO THE CLI
def main():
    cli.add_command(version)
    cli.add_command(setup)
    cli.add_command(start)
    cli.add_command(stop)
    cli.add_command(ssh)

    cli()

if __name__ == '__main__':
    main()
