import os, re
from src.mlvm import Mlvm
from src import const

class Cli():
    def __init__(self):
        self.mlvm = Mlvm()

    # help='Display the current version of this CLI'
    def version(self):
        changelog_txt = open("CHANGELOG.md").read()
        version = re.findall(r"\[\d.*\].*", changelog_txt)[0]
        print(f"Azure ML VM CLI version {version}")

    # help="Create/Link your VM and set up this CLI to your path"
    # '--vm-name', help="If not set, you will be prompted to enter a vm name. Recommended format: ds-vm-<yourname>"
    def setup(self, workspace=const.DEFAULT_WORKSPACE, resource_group=const.DEFAULT_RESOURCE_GROUP, subscription_id=const.DEFAULT_SUBSCRIPTION_ID,
              vm_name=None, vm_size=const.DEFAULT_VM_SIZE, ssh_user=const.DEFAULT_SSH_USER,
              ssh_public_key_file=os.path.join(const.SSH_DIR,'id_rsa.pub'), ssh_private_key_file=os.path.join(const.SSH_DIR,'id_rsa')):
        return self.mlvm.setup(workspace, resource_group, subscription_id, vm_name, vm_size, ssh_user, ssh_public_key_file, ssh_private_key_file)

    # help="Pull the latest mlvm version, update the conda env, and generate new executable"
    def update(self):
        return self.mlvm.update()

    # help='Start up your Azure ML VM'
    # '-w', '--wait', help='Wait for the VM to become available')
    def start(self, wait=False):
        return self.mlvm.start(wait)

    # name='stop', help='Shut down your Azure ML VM'
    # '-w', '--wait', help='Wait for the VM to shut down')
    def stop(self, wait=False):
        return self.mlvm.stop(wait)

    # help='SSH into your Azure ML VM'
    def ssh(self):
        return self.mlvm.ssh()
