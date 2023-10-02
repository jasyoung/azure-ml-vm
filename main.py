import click
import re
import os
import yaml
from src import const
from lib import log
from azureml.core import Workspace
from azureml.core.authentication import ServicePrincipalAuthentication
from azureml.core.compute import ComputeInstance
from azureml.core.compute_target import ComputeTargetException

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
@click.option('--resource-group', default=const.DEFAULT_RESOURCE_GROUP)
@click.option('--subscription-id', default=const.DEFAULT_SUBSCRIPTION_ID)
@click.option('--vm-size', default=const.DEFAULT_VM_SIZE)
def setup(workspace, resource_group, subscription_id, vm_size):
    ws = get_ws({'workspace_name': workspace, 'resource_group': resource_group, 'subscription_id': subscription_id})
    vm_linked = link_vm(ws, vm_size)
    if not vm_linked:
        yn = log.yn("Try to continue with setup anyway? ")
        if not yn:
            log.info('Exiting setup...')
            return

    setup_ssh()
    setup_cli()

@click.command(help='Start up your Azure ML VM')
@click.option('-w', '--wait', default=False, help='Wait for the VM to become available')
def start(wait):
    azureml_configs = yaml.load(open(const.AZUREML_CONFIG_FILE))
    vm = ComputeInstance(get_ws(), azureml_configs['vm_name'])
    vm.start(wait_for_completion=wait)

@click.command(help='Shut down your Azure ML VM')
def stop():
    azureml_configs = yaml.load(open(const.AZUREML_CONFIG_FILE))
    vm = ComputeInstance(get_ws(azureml_configs), azureml_configs['vm_name'])
    vm.stop()

@click.command(help='SSH into your Azure ML VM')
def ssh():
    pass


## NON COMMANDS

def link_vm(workspace, vm_size):
    vm_name = log.usr_in("Enter name for your vm. Recommended format: ds-vm-<yourname> : ")
    vm_provisioned = provision_vm(workspace, vm_name, vm_size) # provision vm if doesn't exist, else skip this step
    if not vm_provisioned:
        return False
    save_azureml_config(workspace, vm_name)
    return True

# azureml_config should be a dict with keys workspace_name, resource_group, and subscription_id
def get_ws(azureml_config=None):
    if azureml_config is None:
        azureml_config = load_azureml_config()

    log.info("Authenticating...")

    if os.environ.get("BUILD_BUILDID") is not None: 
        svc_pr = ServicePrincipalAuthentication(
            tenant_id=os.environ.get("TENANT_ID"),
            service_principal_id= os.environ.get("CLIENTID"), 
            service_principal_password= os.environ.get("SECRET")
            )
    else:
        svc_pr = None

    return Workspace.get(name=azureml_config['workspace_name'], subscription_id=azureml_config['subscription_id'],
                         resource_group=azureml_config['resource_group'], auth=svc_pr)

def provision_vm(workspace, vm_name, vm_size):
    try:
        _ = ComputeInstance(workspace=workspace, name=vm_name)
        log.info(f'Found existing VM {vm_name} in {workspace}')
    except ComputeTargetException:
        yn = log.yn(f'Could not find existing VM {vm_name}. Create? (y/n) ')
        if yn is False:
            log.warn("Did not provision VM")
            return False

        compute_config = ComputeInstance.provisioning_configuration(
            vm_size=vm_size,
            ssh_public_access=False,
            # vnet_resourcegroup_name='<my-resource-group>',
            # vnet_name='<my-vnet-name>',
            # subnet_name='default',
            # admin_user_ssh_public_key='<my-sshkey>'
        )
        instance = ComputeInstance.create(workspace, vm_name, compute_config)
        instance.wait_for_completion(show_output=True)
        return True

def parse_ws_id(ws_id):
    # format: /subscriptions/<subscription_id>/resourceGroups/<resource_group>/providers/Microsoft.MachineLearningServices/workspaces/<workspace_name>
    ws_id = ws_id.split('/')
    return {'subscription_id': ws_id[2],
            'resource_group': ws_id[4],
            'worspace_name': ws_id[8]
            }

def save_azureml_config(workspace, vm_name):
    with open(const.AZUREML_CONFIG_FILE, 'w') as azureml_config:
        # save your azureml compute settings
        ws_details = parse_ws_id(workspace.get_details()['id'])
        azureml_compute_settings = {
            'workspace_name': ws_details['workspace_name'],
            'subscription_id': ws_details['subscription_id'],
            'resource_group': ws_details['resource_group'],
            'vm_name': vm_name
        }
        yaml.dump(azureml_compute_settings, azureml_config)

def load_azureml_config():
    with open(const.AZUREML_CONFIG_FILE, 'r') as azureml_config:
        return yaml.load(azureml_config)

def setup_ssh():
    pass

def setup_cli():
    pass

## ADD COMMANDS TO THE CLI

cli.add_command(version)
cli.add_command(setup)
cli.add_command(link_vm)
cli.add_command(start)
cli.add_command(stop)
cli.add_command(ssh)

cli()