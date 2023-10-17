import string, os, shutil, socket, subprocess, json, paramiko, git
from cryptography.hazmat import primitives as crypto
import PyInstaller.__main__
from src import const
from lib import log
from lib.conda import Conda
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.ai.ml import MLClient
from azure.ai.ml.entities import ComputeInstance, ComputeInstanceSshSettings


class Mlvm():

    def __init__(self):
        __class__.create_config_file_if_not_exists()
        self.azureml_config = self.load_azureml_config()
        self.ml_client = None # we'll create this as needed
        self.compute_instance = None # we'll set this as needed


    ## COMMAND IMPLEMENTATIONS

    def setup(self, workspace, resource_group, subscription_id, vm_name, vm_size, ssh_user, ssh_public_key_file, ssh_private_key_file):
        log.info(f'got args {workspace, resource_group, subscription_id, vm_name, vm_size, ssh_user, ssh_public_key_file, ssh_private_key_file}', verbose=True)
        # validate the vm name and vm size
        if not vm_name is None and not __class__.validate_vm_name(vm_name):
            log.error("Invalid vm name. Must be between 2-16 chars and contain only letters, numbers, or -")
        if not __class__.validate_vm_size(vm_size): # vm_size should not be None. It has a default.
            log.error(f"Invalid vm size. It must be one of {const.VALID_VM_SIZES}")
        # populate the azureml config with the supplied arguments
        self.initialize_azureml_config(workspace, resource_group, subscription_id, vm_name, vm_size, ssh_user, ssh_public_key_file, ssh_private_key_file)

        self.set_ml_client()
        ssh_settings = self.setup_ssh()
        vm_linked = self.link_vm(ssh_settings) # either sets self.compute_instance and returns True or leaves it as None and returns False
        if not vm_linked:
            log.error("Didn't link VM. Setup aborted.")
        self.setup_cli() # create the cli executable add it to PATH
        self.setup_sf_connection()

    def update(self):
        log.info("Pulling latest version of mlvm from git")
        git.cmd.Git(os.path.dirname(__file__)).pull()
        log.info(f'Updating the mlvm conda env')
        Conda().update_env()
        self.setup_cli()

    def start(self, wait):
        self.set_ml_client()
        poller = self.ml_client.compute.begin_start(self.azureml_config['vm_name'])
        log.info(f"Compute instance {self.azureml_config['vm_name']} is starting")
        if wait:
            poller.wait()
            log.info(f"Compute instance {self.azureml_config['vm_name']} has started")

    def stop(self, wait):
        self.set_ml_client()
        poller = self.ml_client.compute.begin_stop(self.azureml_config['vm_name'])
        log.info(f"Compute instance {self.azureml_config['vm_name']} is stopping")
        if wait:
            poller.wait()
            log.info(f"Compute instance {self.azureml_config['vm_name']} has stopped")

    def ssh(self):
        log.info("Starting ssh client", verbose=True)
        ssh_client = paramiko.SSHClient()
        ssh_client.load_host_keys(const.SSH_KNOWN_HOSTS)
        log.info(f"Connecting to {self.azureml_config['ssh_user']}@{self.azureml_config['vm_public_ip']}:{const.SSH_PORT}", verbose=True)
        try:
            # this is just to make sure we can connect. It's very difficult for paramiko to open an interactive shell session
            ssh_client.connect(self.azureml_config['vm_public_ip'], port=const.SSH_PORT, username=self.azureml_config['ssh_user'], 
                            key_filename=self.azureml_config['ssh_private_key_file'], timeout=4)
            ssh_client.close()
            log.info("Connected! Invoking shell", verbose=True)
            os.system(f"ssh -i {self.azureml_config['ssh_private_key_file']} {self.azureml_config['ssh_user']}@{self.azureml_config['vm_public_ip']} -p {self.const.SSH_PORT}")
        except socket.timeout:
            log.warn(f"SSH connection to {self.azureml_config['vm_public_ip']} timed out.")
            self.set_ml_client()
            if not self.vm_running():
                log.warn(f"VM {self.azureml_config['vm_name']} is not running.")
                if log.yn("Start it up?"):
                    self.start(True)
                    self.ssh()
                else:
                    log.warn(f"Aborted.")
        except KeyError:
            log.error(f"Make sure your {const.AZUREML_CONFIG_FILE} exists and has the required items set")
        except Exception as ex:
            log.error(f"""{ex}
                    Could not connect via SSH.
                    Check your ssh-public-key and the VM's ssh settings in the Azure portal.
                    Azure ML Compute portal: {self.get_ml_computes_url()}""")


    ## STATIC METHODS

    @staticmethod
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

    @staticmethod
    def validate_vm_size(vm_size):
        return vm_size in const.VALID_VM_SIZES
    
    @staticmethod
    def create_config_file_if_not_exists():
        if not os.path.isfile(const.AZUREML_CONFIG_FILE):
            log.warn(f"{const.AZUREML_CONFIG_FILE} file not found. Generating one.", verbose=True)
            with open(const.AZUREML_CONFIG_FILE, "w") as fo:
                fo.write(json.dumps({}))

    @staticmethod
    def enter_vm_name():
        while True:
            vm_name = log.usr_in("Enter name for your vm. Recommended format: ds-vm-<yourname> :")
            if not __class__.validate_vm_name(vm_name):
                log.warn("Invalid vm name. Must be between 2-16 chars and contain only letters, numbers, or -")
                continue
            return vm_name

    @staticmethod
    def load_azureml_config():
        log.info(f"Loading {const.AZUREML_CONFIG_FILE}", verbose=True)
        try:
            with open(const.AZUREML_CONFIG_FILE, 'r') as azureml_config:
                return json.load(azureml_config)
        except FileNotFoundError:
            log.error(f"{const.AZUREML_CONFIG_FILE} not found. Please run `mlvm setup` to create it.")

    @staticmethod
    def authenticate():
        log.info("Authenticating...", verbose=True)
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
    
    @staticmethod
    def setup_cli():
        log.info("Generating the cli executable", verbose=True)
        try:
            PyInstaller.__main__.run(['main.py', '--clean', '--name', const.EXE_NAME]) # generate the executable
        except PyInstaller.isolated._parent.SubprocessDiedError:
            # something weird happened. Just delete everything in build/mlvm and dist/mlvm first
            shutil.rmtree(os.path.join('build', 'mlvm'))
            shutil.rmtree(os.path.join('dist', 'mlvm'))
            PyInstaller.__main__.run(['main.py', '--clean', '--name', const.EXE_NAME]) # generate the executable
        # path to the newly generated executable (src)
        path_to_exe = os.path.join(os.path.dirname(__file__), 'dist', const.EXE_NAME, const.EXE_NAME)
        if os.name == 'nt': # Windows
            path_to_exe += '.exe'
        log.info(f"Path to the executable: {path_to_exe}", verbose=True)
        # path to the soft link (dst)
        linked_file = __class__.select_loc_for_linked_file(const.EXE_NAME)
        log.info(f"Path to the soft link: {linked_file}", verbose=True)
        # Assuming the linked file is in your PATH, this cli will be callable as mlvm
        log.info('Linking files', verbose=True)
        try:
            os.symlink(path_to_exe, linked_file)
        except FileExistsError:
            log.warn(f"{linked_file} already exists. Relinking.", verbose=True)
            os.remove(linked_file)
            os.symlink(path_to_exe, linked_file)
        log.info("Assuming the linked file is in your PATH, this cli will be callable as mlvm")

    @staticmethod
    def select_loc_for_linked_file():
        log.info("Finding a location for the linked file", verbose=True)
        # select the env dir that contains the exe_name, which is assumed to be the same as the env_name
        env_dirs = json.loads(subprocess.check_output('conda env list -v --json'.split(' '), text=True))
        for env_dir in env_dirs['envs']:
            if env_dir.endswith(const.EXE_NAME):
                return os.path.join(env_dir, const.EXE_NAME)
        log.error('Could not find conda env mlvm. Please find the mlvm executable and link it to your PATH manually.')


    ## OTHER METHODS

    # this ensures that self and the config file match. Use this when adding/updating config attributes
    def add_item_to_azureml_config(self, key, value, allow_none=False, prompt_overwrite=False):
        log.info(f"Adding {key}: {value} to {const.AZUREML_CONFIG_FILE}", verbose=True)
        if not allow_none and value is None:
            log.error(f"Can't accept value of None for {key}")
        existing_value = self.azureml_config.get(key)
        # see if the user wants to overwrite a new value into their config
        # only necessary if the existing value is not none; !still necessary if the new value is None!
        if prompt_overwrite and existing_value and existing_value != value:
            if not log.yn(f"Overwrite {{\"{key}\": \"{existing_value}\"}} with {{\"{key}\": \"{value}\"}}?"):
                log.info(f"keeping {key}: {existing_value} in {const.AZUREML_CONFIG_FILE}", verbose=True)
                return existing_value
        elif existing_value == value: # If they're already the same then who cares
            return value
        self.azureml_config[key] = value
        with open(const.AZUREML_CONFIG_FILE, 'w') as file:
            file.write(json.dumps(self.azureml_config))
        return value

    def initialize_azureml_config(self, workspace, resource_group, subscription_id, vm_name, vm_size, ssh_user, ssh_public_key_file, ssh_private_key_file):
        log.info(f'got args {workspace, resource_group, subscription_id, vm_name, vm_size, ssh_user, ssh_public_key_file, ssh_private_key_file}', verbose=True)
        self.add_item_to_azureml_config('resource_group', resource_group, prompt_overwrite=True)
        self.add_item_to_azureml_config('subscription_id', subscription_id, prompt_overwrite=True)
        self.add_item_to_azureml_config('workspace', workspace, prompt_overwrite=True)
        self.add_item_to_azureml_config('ssh_user', ssh_user, prompt_overwrite=True)
        self.add_item_to_azureml_config('vm_name', vm_name, allow_none=True, prompt_overwrite=True)
        self.add_item_to_azureml_config('vm_size', vm_size, prompt_overwrite=True)
        self.add_item_to_azureml_config('ssh_public_key_file', ssh_public_key_file, prompt_overwrite=True)
        self.add_item_to_azureml_config('ssh_private_key_file', ssh_private_key_file, prompt_overwrite=True)

    # const.AZUREML_CONFIG_FILE should be in json format with keys workspace_name, resource_group, and subscription_id
    def set_ml_client(self):
        if self.ml_client:
            log.warn("ML Client is already set. Not recreating.", verbose=True)
        log.info("Getting ML Client", verbose=True)
        credential = __class__.authenticate()
        self.ml_client = MLClient.from_config(credential=credential, path=const.AZUREML_CONFIG_FILE)

    def setup_ssh(self):
        log.info("Setting up SSH", verbose=True)
        # save new/existing ssh key file paths in azureml_config
        log.info("Saving the new SSH key file paths in azureml_config")
        self.link_ssh_keypair()
        return ComputeInstanceSshSettings(ssh_public_access='Enabled', admin_public_key=self.azureml_config['ssh_public_key_file'],
                                          admin_user_name=self.azureml_config['ssh_user'], ssh_port=const.SSH_PORT)

    def link_ssh_keypair(self):
        if not os.path.isfile(self.azureml_config['ssh_public_key_file']):
            log.warn(f"Could not find existing public key file {self.azureml_config['ssh_public_key_file']}")
            if log.yn(f"Generate new ssh keypair with private key at {self.azureml_config['ssh_private_key_file']} \
                      and public key at {self.azureml_config['ssh_public_key_file']}?"):
                # generate a new ssh keypair if we don't have one
                # Assumes we don't have one if the specified ssh_public_key_file doesn't exist
                self.generate_ssh_keypair()
            else:
                log.error("Did not link ssh keypair. To link an ssh keypair, please specify the file locations for existing ones, \
                          use the default locations, or generate new keys. You can specify specific key locations with the \
                          --ssh-public-key-file and --ssh-private-key-file options in `mlvm setup`\n \
                          Aborting.")
        else: # assumes we already have an ssh keypair so we just need to note them in the azureml config
            # except, we should already have those file locations set by this point, so we don't need to do anything
            pass

    def generate_ssh_keypair(self):
        log.info("Generating SSH keypair", verbose=True)
        private_key = crypto.asymmetric.rsa.generate_private_key(
            public_exponent=const.RSA_PUBLIC_EXP,
            key_size=const.RSA_KEY_SIZE
        )
        public_key = private_key.public_key()
        if not os.path.exists(const.SSH_DIR):
            os.makedirs(const.SSH_DIR)
        log.info("Saving SSH keys", verbose=True)
        self.save_private_ssh_key(private_key)
        self.save_public_ssh_key(public_key)

    def save_private_ssh_key(self, private_key):
        private_pem = private_key.private_bytes(
            encoding=crypto.serialization.Encoding.PEM,
            format=crypto.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=crypto.serialization.NoEncryption()
        )
        with open(self.azureml_config['ssh_private_key_file'], 'wb') as f:
            f.write(private_pem)

    def save_public_ssh_key(self, public_key):
        public_pem = public_key.public_bytes(
            encoding=crypto.serialization.Encoding.PEM,
            format=crypto.serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(self.azureml_config['ssh_public_key_file'], 'wb') as f:
            f.write(public_pem)

    def load_public_ssh_key(self):
        log.info("Loading public ssh key", verbose=True)
        with open(self.azureml_config['ssh_public_key_file'], 'rb') as key_file:
            try:
                return crypto.serialization.load_pem_public_key(key_file.read())
            except ValueError as ex:
                log.error(f"""{ex} Your key needs to be in the PEM format. 
                        Please look up how to encode it as such (recommended) or generate new ssh keys.""")

    def add_to_known_hosts(public_ip):
        transport = paramiko.Transport(public_ip)
        transport.connect()
        key = transport.get_remote_server_key()
        transport.close()
        hostfile = paramiko.HostKeys(filename=const.SSH_KNOWN_HOSTS)
        hostfile.add(hostname=public_ip, key=key, keytype=key.get_name())
        hostfile.save(filename=const.SSH_KNOWN_HOSTS)

    def link_vm(self, ssh_settings):
        log.info("Linking vm", verbose=True)
        if self.azureml_config.get('vm_name') is None: # prefer .get() to [] here because we're filling it in here anyway
            try: # look for vm_name in the configs
                if not log.yn(f"Found vm_name {self.azureml_config['vm_name']} in {const.AZUREML_CONFIG_FILE}. Link this one?"):
                    self.add_item_to_azureml_config('vm_name', __class__.enter_vm_name())
            except KeyError:
                self.add_item_to_azureml_config('vm_name', __class__.enter_vm_name())
        # provision vm if doesn't exist
        # if successful, self.compute_instance will be populated
        self.provision_vm(ssh_settings)
        if not self.compute_instance:
            log.warn("Did not provision VM")
            return False
        self.add_item_to_azureml_config('vm_public_ip', self.compute_instance.network_settings.public_ip_address)
        self.add_to_known_hosts(self.azureml_config['vm_public_ip'])
        return True

    def provision_vm(self, ssh_settings):
        try:
            self.compute_instance = self.ml_client.compute.get(self.azureml_config['vm_name'])
            log.info(f"Found existing VM {self.azureml_config['vm_name']} in {self.ml_client.workspace_name}")
            log.info(f"If this is yours, feel free to continue with setup to link it.")
            yn = log.yn("Would you like to continue?")
            return yn # True if we want to continue because we have self.compute_instance set
        except ResourceNotFoundError:
            yn = log.yn(f"Could not find existing VM {self.azureml_config['vm_name']}. Create?")
            if not yn:
                return False
            log.info(f"Provisioning VM {self.azureml_config['vm_name']}. This may take a few minutes.")
            self.compute_instance = ComputeInstance(
                name=self.azureml_config['vm_name'], size=self.azureml_config['vm_size'], ssh_public_access_enabled=True,
                ssh_settings=ssh_settings, idle_time_before_shutdown_minutes=const.IDLE_TIME_BEFORE_SHUTDOWN_MINUTES,
                setup_scripts=None, enable_node_public_ip=True
            )
            self.compute_instance = self.ml_client.compute.begin_create_or_update(self.compute_instance).result()
            return True

    def vm_running(self):
        self.compute_instance = self.ml_client.compute.get(self.azureml_config['vm_name'])
        return 'running' == self.compute_instance.state

    def get_ml_computes_url(self):
        url = 'https://ml.azure.com/compute/list/instances?wsid=/subscriptions/'
        url += self.azureml_config['subscription_id'] + '/resourceGroups/'
        url += self.azureml_config['resource_group'] + '/providers/Microsoft.MachineLearningServices/workspaces/'
        url += self.azureml_config['workspace_name'] + '&tid=1aff0669-ee5f-40b8-9800-b5ec4f39c48e'
        return url

    def setup_sf_connection():
        log.warn("Snowflake Connection setup has not been implemented yet.")
        pass
