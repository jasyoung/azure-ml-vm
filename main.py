#!/usr/bin/env python

import click
import re
import string
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

@cli.command(help='Display the current version of this CLI',
             context_settings={'ignore_unknown_options': True, 'allow_extra_args': True})
def version():
    changelog_txt = open("CHANGELOG.md").read()
    version = re.findall(r"\[\d.*\].*", changelog_txt)[0]
    click.echo(f"Azure ML VM CLI version {version}")

@cli.command(help="Create/Link your VM and set up this CLI to your path",
             context_settings={'ignore_unknown_options': True, 'allow_extra_args': True})
@click.option('--workspace', default=const.DEFAULT_WORKSPACE)
@click.option('--resource-group', default=const.DEFAULT_RESOURCE_GROUP)
@click.option('--subscription-id', default=const.DEFAULT_SUBSCRIPTION_ID)
@click.option('--vm-name', default=None, help="If not set, you will be prompted to enter a vm name. Recommended format: ds-vm-<yourname>")
@click.option('--vm-size', default=const.DEFAULT_VM_SIZE)
@click.option('--ssh-user', default=const.DEFAULT_SSH_USER)
@click.option('--ssh-public-key-file', default=os.path.join(const.SSH_DIR,'id_rsa.pub'))
@click.option('--ssh-private-key-file', default=os.path.join(const.SSH_DIR,'id_rsa'))
def setup(workspace, resource_group, subscription_id, vm_name, vm_size, ssh_user, ssh_public_key_file, ssh_private_key_file):
    if not vm_name is None and not validate_vm_name(vm_name):
        log.error("Invalid vm name. Must be between 2-16 chars and contain only letters, numbers, or -")
    if not vm_size is None and not validate_vm_size(vm_size):
        log.error(f"Invalid vm size. It must be one of {const.VALID_VM_SIZES}")
    resource_group, subscription_id = set_ml_env_vars(resource_group, subscription_id)
    # configure_azure_credentials()
    ml_client = get_ml_client({'workspace_name': workspace, 'resource_group': resource_group, 'subscription_id': subscription_id})
    vm_linked = link_vm(ml_client, vm_name, vm_size) # returns a ComputeInstance object, else returns False
    if not vm_linked:
        log.error("Didn't link VM. Setup aborted.")
    setup_ssh(ml_client, vm_linked, ssh_user, ssh_public_key_file, ssh_private_key_file)
    setup_cli(const.EXE_NAME) # create the cli executable add it to PATH
    setup_sf_connection()

@cli.command(help="Pull the latest mlvm version, update the conda env, and generate new executable",
             context_settings={'ignore_unknown_options': True, 'allow_extra_args': True})
def update():
    log.info("Pulling latest version of mlvm from git")
    git.cmd.Git(os.path.dirname(__file__)).pull()
    log.info(f'Updating the mlvm conda env')
    Conda().update_env()
    setup_cli(const.EXE_NAME)

@cli.command(help='Start up your Azure ML VM',
             context_settings={'ignore_unknown_options': True, 'allow_extra_args': True})
@click.option('-w', '--wait', default=False, help='Wait for the VM to become available')
def start(wait):
    azureml_config = load_azureml_config()
    ml_client = get_ml_client(azureml_config)
    poller = ml_client.compute.begin_start(azureml_config['vm_name'])
    if wait:
        log.info("Waiting for compute instance to start", verbose=True)
        poller.wait()

@cli.command(help='Shut down your Azure ML VM',
             context_settings={'ignore_unknown_options': True, 'allow_extra_args': True})
@click.option('-w', '--wait', default=False, help='Wait for the VM to shut down')
def stop(wait):
    azureml_config = load_azureml_config()
    ml_client = get_ml_client(azureml_config)
    poller = ml_client.compute.begin_stop(azureml_config['vm_name'])
    if wait:
        poller.wait()

@cli.command(help='SSH into your Azure ML VM',
             context_settings={'ignore_unknown_options': True, 'allow_extra_args': True})
def ssh():
    azureml_config = load_azureml_config()
    log.info("Starting ssh client", verbose=True)
    ssh_client = paramiko.SSHClient()
    log.info("Looking for ssh keys", verbose=True)
    ssh_client.look_for_keys(True)
    log.info(f"Connecting to {azureml_config['ssh_user']}@{azureml_config['vm_public_ip']}:{const.SSH_PORT}", verbose=True)
    ssh_client.connect(azureml_config['vm_public_ip'], port=const.SH_PORT, username=azureml_config['ssh_user'])
    ssh_client.close()


## NON COMMANDS

def validate_vm_name(vm_name):
    log.info(f"Validating supplied vm name {vm_name}", verbose=True)
    if len(vm_name) < 2 or len(vm_name) > 16:
        log.info("Supplied name is not the right length", verbose=True)
        return False
    valid_chars = set(string.ascii_lowercase + string.ascii_uppercase + string.digits + '-')
    valid = set(vm_name) <= valid_chars
    if not valid:
        log.info("Supplied name has invalid characters", verbose=True)
    return valid

def validate_vm_size(vm_size):
    return vm_size in const.VALID_VM_SIZES

# try to use the passed var first
# if that's not set then try the os.environ
# else use the value in const.py and set to os.environ
def set_ml_env_vars(resource_group, subscription_id):
    if resource_group is None:
        resource_group = get_env_var('RESOURCE_GROUP_NAME', const.DEFAULT_RESOURCE_GROUP)
    if subscription_id is None:
        subscription_id = get_env_var('AZURE_SUBSCRIPTION_ID', const.DEFAULT_SUBSCRIPTION_ID)
    return resource_group, subscription_id

def get_env_var(env_var, default):
    log.info(f"Looking for environment variable {env_var}", verbose=True)
    try:
        return os.environ[env_var]
    except KeyError:
        log.info(f"{env_var} not found. Using {default}", verbose=True)
        return default

# azureml_config should be a dict with keys workspace_name, resource_group, and subscription_id
def get_ml_client(azureml_config=None):
    log.info("Getting ML Client", verbose=True)
    if azureml_config is None:
        azureml_config = load_azureml_config()
    credential = authenticate()
    try:
        ml_client = MLClient.from_config(credential=credential)
    except Exception as ex:
        log.warn("Config file not found. Generating one.", verbose=True)
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
        log.warn("Could not get token. We have to log in to Azure interactively in the browser", verbose=True)
        # Fall back to InteractiveBrowserCredential in case DefaultAzureCredential not work
        # This will open a browser page for
        credential = InteractiveBrowserCredential()
    return credential

def link_vm(ml_client, vm_name, vm_size):
    log.info("Linking vm", verbose=True)
    if vm_name is None:
        try: # look for vm_name in the configs
            vm_name = load_azureml_config()['vm_name']
            if not log.yn(f"Found vm_name {vm_name} in {const.AZUREML_CONFIG_FILE}. Link this one?"):
                vm_name = enter_vm_name()
        except KeyError:
            vm_name = enter_vm_name()
    vm_provisioned = provision_vm(ml_client, vm_name, vm_size) # provision vm if doesn't exist
    if not vm_provisioned:
        log.warn("Did not provision VM")
        return False
    add_item_to_azureml_config('vm_name', vm_name)
    return vm_provisioned # returns a ComputeInstance object, else returns False

def enter_vm_name():
    while True:
        vm_name = log.usr_in("Enter name for your vm. Recommended format: ds-vm-<yourname> :")
        if not validate_vm_name(vm_name):
            log.warn("Invalid vm name. Must be between 2-16 chars and contain only letters, numbers, or -")
            continue
        return vm_name

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
    log.info(f"Adding {key}: {value} to {const.AZUREML_CONFIG_FILE}", verbose=True)
    azureml_config = load_azureml_config()
    azureml_config[key] = value
    with open(const.AZUREML_CONFIG_FILE, 'w') as file:
        file.write(json.dumps(azureml_config))
    return value

def load_azureml_config():
    log.info(f"Loading {const.AZUREML_CONFIG_FILE}", verbose=True)
    with open(const.AZUREML_CONFIG_FILE, 'r') as azureml_config:
        return json.load(azureml_config)

def setup_ssh(ml_client, compute_instance, ssh_user, public_key_file, private_key_file):
    log.info("Setting up SSH", verbose=True)
    # save new/existing ssh key file paths in azureml_config
    log.info("Saving the new SSH key file paths in azureml_config")
    link_ssh_keypair(public_key_file, private_key_file)

    # update the compute instance with ssh settings
    log.info("Updating the SSH settings for the compute instance")
    ssh_settings = ComputeInstanceSshSettings(ssh_public_access='Enabled', admin_public_key=public_key_file,
                                              admin_user_name=ssh_user, ssh_port=const.SSH_PORT)
    compute_instance.ssh_settings = ssh_settings
    log.info(f"network_settings: {compute_instance.network_settings}")
    compute_instance = ml_client.compute.begin_update(compute_instance).result()
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
    log.info("Generating SSH keypair", verbose=True)
    private_key = crypto.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    if not os.path.exists(const.SSH_DIR):
        os.makedirs(const.SSH_DIR)
    log.info("Saving SSH keys", verbose=True)
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

def setup_cli(exe_name):
    log.info("Generating the cli executable", verbose=True)
    PyInstaller.__main__.run(['main.py', '--clean', '--name', exe_name]) # generate the executable
    # path to the newly generated executable (src)
    path_to_exe = os.path.join(os.path.dirname(__file__), 'dist', exe_name, exe_name)
    if os.name == 'nt': # Windows
        path_to_exe += '.exe'
    log.info(f"Path to the executable: {path_to_exe}", verbose=True)
    # path to the soft link (dst)
    linked_file = select_loc_for_linked_file(exe_name)
    log.info(f"Path to the soft link: {linked_file}", verbose=True)
    # Assuming the linked file is in your PATH, this cli will be callable as mlvm
    log.info('Linking files', verbose=True)
    os.symlink(path_to_exe, linked_file)
    log.info("Assuming the linked file is in your PATH, this cli will be callable as mlvm", verbose=True)

def select_loc_for_linked_file(exe_name):
    log.info("Finding a location for the linked file", verbose=True)
    # select the env dir that contains the exe_name, which is assumed to be the same as the env_name
    env_dirs = json.loads(subprocess.check_output('conda env list -v --json'.split(' '), text=True))
    for env_dir in env_dirs['envs']:
        if env_dir.endswith(exe_name):
            return os.path.join(env_dir, exe_name)
    log.error('Could not find conda env mlvm. Please find the mlvm executable and link it to your PATH manually.')

def setup_sf_connection():
    log.warn("Snowflake Connection setup has not been implemented yet.", verbose=True)
    pass

# We shouldn't need to use this since it should be taken care of
# If it turns out we don't need it, remove azure-cli dependency
def ensure_logged_in():
    if 0 != subprocess.check_call('az login --use-device-code'.split(' ')):
        log.error("Couldn't log in to Azure")

# We shouldn't need to use this since ComputeInstanceSshSettings() only requires a public key file
# If it turns out we do need it, the call should go right before ComputeInstanceSshSettings() above
def load_public_ssh_key():
    log.info("Loading public ssh key", verbose=True)
    public_key_file = load_azureml_config()['public_ssh_key_file']
    with open(public_key_file, 'rb') as key_file:
        try:
            return crypto.serialization.load_pem_public_key(
                key_file.read()
            )
        except ValueError as ex:
            log.error(f"""{ex} Your key needs to be in the PEM format. 
                      Please look up how to encode it as such (recommended) or generate new ssh keys.""")

## ADD COMMANDS TO THE CLI
def main():
    cli.add_command(version)
    cli.add_command(setup)
    cli.add_command(start)
    cli.add_command(stop)
    cli.add_command(ssh)

    cli()
    # cli(log.is_verbose(), log.is_debug())

if __name__ == '__main__':
    main()
