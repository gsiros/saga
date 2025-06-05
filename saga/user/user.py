import requests
import base64
import saga.config
import saga.common.crypto as sc
from saga.ca.CA import get_SAGA_CA
import os
import json
from saga.common.logger import Logger as logger
from saga.common.overhead import Monitor


def get_provider_cert(email):
    """
    This is a 'smarter' way to get the provider's certificate. This function uses the requests library
    to get the certificate of the server.

    Args:
        email: The email of the user.
    """
    PROVIDER_ENDPOINT = saga.config.PROVIDER_CONFIG.get('endpoint')
    response = requests.get(PROVIDER_ENDPOINT+"/certificate", verify=saga.config.CA_CERT_PATH, cert=(
        saga.config.USER_WORKDIR+"/keys/"+email+".crt", saga.config.USER_WORKDIR+"/keys/"+email+".key"
    ))
    cert_bytes = base64.b64decode(response.json().get('certificate'))
    cert = sc.bytesToX509Certificate(cert_bytes)
    
    return cert

# Instanciate the CA object:
CA = get_SAGA_CA()
global PROVIDER_CERT, PK_Prov

# User state:
provider_tokens = []
uid = None
state = {}
state['keys'] = {}
state['agents'] = {}

monitor = Monitor()

def register(email: str=None, password: str=None):
    """
    Register a new user with the provider. This function generates the user's cryptographic material,
    including a signing key pair and a user certificate, and sends them to the provider for registration.
    If the user already exists, the registration will fail.

    Args:
        email: The email of the user. If None, the user will be prompted to enter it.
        password: The password of the user. If None, the user will be prompted to enter it.
    """

    email = input("Enter email: ") if email is None else email
    password = input("Enter password: ") if password is None else password
    monitor.start("user:user_register")
    logger.log("USER", f"Generating user cryptographic material...")
    # Generate user signing key pair:
    sk_u, pk_u = sc.generate_ed25519_keypair()

    # Generate user certificate:
    custom_user_config = saga.config.USER_DEFAULT_CONFIG.copy()
    custom_user_config["COMMON_NAME"] = email
    user_cert = CA.sign(
        public_key=pk_u, # PK_U 
        config=custom_user_config
    )

    # Save the keys to disk:
    if not os.path.exists(saga.config.USER_WORKDIR+"/keys"):
        os.mkdir(saga.config.USER_WORKDIR+"/keys")
    logger.log("CRYPTO", f"Saving user keys to {saga.config.USER_WORKDIR}/keys/{email}")
    sc.save_ed25519_keys(saga.config.USER_WORKDIR+"/keys/"+email, sk_u, pk_u)
    sc.save_x509_certificate(saga.config.USER_WORKDIR+"/keys/"+email, user_cert)

    monitor.stop("user:user_register")
    logger.log("OVERHEAD", f"user:user_register: {monitor.elapsed('user:user_register')}")
    response = requests.post(f"{saga.config.PROVIDER_CONFIG.get('endpoint')}/register", json={
        'uid': email, # uid
        'password': password, # pwd 
        # CRYPTOGRAPHIC MATERIAL TO SUBMIT TO THE PROVIDER:
        # - USER CERTIFICATE
        'crt_u': base64.b64encode(
            user_cert.public_bytes(sc.serialization.Encoding.PEM)
        ).decode("utf-8")
    }, verify=saga.config.CA_CERT_PATH, cert=(
        saga.config.USER_WORKDIR+"/keys/"+email+".crt", saga.config.USER_WORKDIR+"/keys/"+email+".key"
    ))
    
    if response.status_code == 201:
        logger.log("PROVIDER", f"User {email} registered successfully.")
        # Store the uid:
        state['uid'] = email
        # Store the key pair:
        state['keys']['signing'] = {
            'public': pk_u,
            'private': sk_u
        }

         # Get the provider's certificate:
        PROVIDER_CERT = get_provider_cert(email)
        # Verify the provider's certificate:
        CA.verify(PROVIDER_CERT) # if the verification fails an exception will be raised.
        PK_Prov = PROVIDER_CERT.public_key()
    else:
        logger.log("PROVIDER", f"User registration failed: {response.json()}")
        # Remove the keys from disk:
        logger.log("CRYPTO", f"Removing user keys from {saga.config.USER_WORKDIR}/keys/{email}")
        os.remove(saga.config.USER_WORKDIR+"/keys/"+email+".key")
        os.remove(saga.config.USER_WORKDIR+"/keys/"+email+".crt")
        os.remove(saga.config.USER_WORKDIR+"/keys/"+email+".pub")        


def login(email: str=None, password: str=None):
    """
    Login an existing user with the provider. This function retrieves the user's cryptographic material
    from disk, sends the login request to the provider, and verifies the provider's certificate.

    Args:
        email: The email of the user. If None, the user will be prompted to enter it.
        password: The password of the user. If None, the user will be prompted to enter it.
    """
    global PROVIDER_CERT, PK_Prov
    email = input("Enter email: ") if email is None else email
    password = input("Enter password: ") if password is None else password

    response = requests.post(f"{saga.config.PROVIDER_CONFIG.get('endpoint')}/login", json={'uid': email, 'password': password}, verify=saga.config.CA_CERT_PATH, cert=(
        saga.config.USER_WORKDIR+"/keys/"+email+".crt", saga.config.USER_WORKDIR+"/keys/"+email+".key"
    )) 
    if response.status_code == 200:
        token = response.json().get("access_token")
        logger.log("PROVIDER", f"User {email} logged in successfully.")
        provider_tokens.append(token)
        state["uid"] = email
        # Load the keys from disk:
        sk_u, pk_u = sc.load_ed25519_keys("./keys/"+email)
        state['keys']['signing'] = {
            'public': pk_u,
            'secret': sk_u
        }

        # Get the provider's certificate:
        PROVIDER_CERT = get_provider_cert(email)
        # Verify the provider's certificate:
        CA.verify(PROVIDER_CERT) # if the verification fails an exception will be raised.
        PK_Prov = PROVIDER_CERT.public_key()

        return token
    else:
        logger.log("PROVIDER", f"Login failed: {response.json()}")
        return None

def register_agent(name=None, device=None,
                   IP=None,
                   port=None,
                   num_one_time_keys=None,
                   contact_rulebook=None,
                   a2a_card=None):
    """
    Register a new agent with the provider. This function generates the agent's cryptographic material,
    including a signing key pair, a device certificate, and one-time access keys. It then sends the
    registration request to the provider.

    Args:
        name: The name of the agent. If None, the user will be prompted to enter it.
        device: The name of the device where the agent is running. If None, the user will be prompted to enter it.
        IP: The IP address of the device where the agent is running. If None, the user will be prompted to enter it.
        port: The port of the device where the agent is running. If None, the user will be prompted to enter it.
        num_one_time_keys: The number of one-time access keys to generate. If None, the user will be prompted to enter it.
        contact_rulebook: The contact rulebook for the agent. If None, the user will be prompted to enter it.
    """
    global PROVIDER_CERT, PK_Prov

    name = input("Enter agent name: ") if name is None else name
    device = input("Enter device name: ") if device is None else device
    IP = input("Enter IP address: ") if IP is None else IP
    port = input("Enter port: ") if port is None else port
    num_one_time_keys = int(input("Enter number of one-time access keys: ")) if num_one_time_keys is None else num_one_time_keys
    if contact_rulebook is None:
        contact_rulebook = input("Enter contact rulebook: ")
        contact_rulebook = json.loads(contact_rulebook) 
    else:
        contact_rulebook = contact_rulebook

    monitor.start("user:agent_register")

    # Assign the aid:
    aid = state['uid'] + ":" + name

    # Generate the device info:
    dev_network_info = {
        "aid":aid, 
        "device":device, 
        "IP":IP, 
        "port":port,
        "a2a_card": a2a_card
    }

    # Generate TLS signing keys for the Agent:
    sk_a, pk_a = sc.generate_ed25519_keypair() # SK_A, PK_A

    # Generate the certificate of the Agent for TLS communication:
    custom_agent_config = saga.config.AGENT_DEFAULT_CONFIG.copy()
    custom_agent_config["COMMON_NAME"] = aid
    custom_agent_config["IP"] = IP
    agent_cert = CA.sign(
        public_key=pk_a, # PK_A
        config=custom_agent_config
    )

    # -- ACCESS CONTROL KEYS -- :
    # Generate long term Access Control Key Pair:
    sac, pac = sc.generate_x25519_keypair()
    crypto_info = {
        "pk_a":pk_a.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw),
        "pac":pac.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw),
        "pk_prov": PK_Prov.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw)
    }

    # Generate One-Time Keys:
    private_one_time_keys = []
    public_one_time_keys = []
    for _ in range(num_one_time_keys):
        private_one_time_key, public_one_time_key = sc.generate_x25519_keypair()
        private_one_time_keys.append(private_one_time_key)
        public_one_time_keys.append(public_one_time_key)

    public_one_time_keys_2_b64 = [base64.b64encode(key.public_bytes(
        encoding=sc.serialization.Encoding.Raw,
        format=sc.serialization.PublicFormat.Raw)).decode("utf-8") for key in public_one_time_keys]

    private_one_time_keys_2_b64 = [base64.b64encode(key.private_bytes(
        encoding=sc.serialization.Encoding.Raw,
        format=sc.serialization.PrivateFormat.Raw,
        encryption_algorithm=sc.serialization.NoEncryption())).decode("utf-8") for key in private_one_time_keys]

    # -- SIGNATURE GENERATIONS -- :
    # Generate the agent signature:
    block = {}
    block.update(dev_network_info)
    block.update(crypto_info)
    agent_sig = state['keys']['signing']['secret'].sign(str(block).encode("utf-8"))

    # Generate the signature of every OTK with the user's secret signing key:
    otk_sigs_2_b64 = []
    for key in public_one_time_keys:
        sig = state['keys']['signing']['secret'].sign(
            key.public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw
            )
        )
        otk_sigs_2_b64.append(base64.b64encode(sig).decode("utf-8"))


    # Collect all the required material for the agent registration application:
    application = {
        # The agent's AID
        'aid': aid, 
        # The agent's device name
        'device': device,
        # The host device IP address
        'IP': IP,
        # The host device port
        'port': port,
        # The agent certificate containing the agent's public signing key
        'agent_cert': base64.b64encode(
            agent_cert.public_bytes(sc.serialization.Encoding.PEM)
        ).decode("utf-8"),
        # Public Access Control Key (PAC):
        'pac': base64.b64encode(pac.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw)).decode("utf-8"),
        # batch of public one-time keys
        'otks': public_one_time_keys_2_b64,
        # CONTACT RULEBOOK:
        'contact_rulebook': contact_rulebook,
        # SIGNATURES:
        'agent_sig': base64.b64encode(agent_sig).decode("utf-8"), # Agent signature
        # and their corresponding signatures
        'otk_sigs': otk_sigs_2_b64, 
        # A2A card (optional)
        'a2a_card': a2a_card,
    }

    monitor.stop("user:agent_register")

    response = requests.post(f"{saga.config.PROVIDER_CONFIG.get('endpoint')}/register_agent", json={
        'uid': state['uid'], # The user's uid
        'jwt': provider_tokens[-1], # Provider's JWT
        'application': application
    }, verify=saga.config.CA_CERT_PATH, cert=(
        saga.config.USER_WORKDIR+"/keys/"+state['uid']+".crt", saga.config.USER_WORKDIR+"/keys/"+state['uid']+".key"
    ))
    
    monitor.start("user:agent_register")
    # Based on the provider's response, store the agent's cryptographic material
    if response.status_code == 201:  
        # Save the agent's cryptographic material
        stamp = response.json().get('stamp')
        logger.log("PROVIDER", f"Agent {name} registered successfully with stamp {stamp}.")  
        state['agents'][name]= {
            'signing_key': {
                'public': pk_a,
                'secret': sk_a
            },
            'access_control': {
                'public': pac,
                'private': sac
            },
            'one_time_keys': [list(zip(private_one_time_keys, public_one_time_keys))],
        }
        # Spawn Agent with the given material:
        
        crt_u = sc.load_x509_certificate(saga.config.USER_WORKDIR+"/keys/"+state['uid']+".crt")

        application.update({
            "stamp": stamp,
            "crt_u": base64.b64encode(
                crt_u.public_bytes(sc.serialization.Encoding.PEM)
            ).decode("utf-8"),
            "secret_signing_key": base64.b64encode(sk_a.private_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PrivateFormat.Raw,
                encryption_algorithm=sc.serialization.NoEncryption()
            )).decode("utf-8"),
            "sac": base64.b64encode(sac.private_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PrivateFormat.Raw,
                encryption_algorithm=sc.serialization.NoEncryption()
            )).decode("utf-8"),
            "sotks": private_one_time_keys_2_b64
        })
        spawn_agent(application)
    else:
        logger.log("PROVIDER", f"Agent registration failed: {response.json()}")
    monitor.stop("user:agent_register")
    logger.log("OVERHEAD", f"user:agent_register: {monitor.elapsed('user:agent_register')}")

def spawn_agent(application):
    """
    This function creates a directory for the agent and dumps the application material in a JSON file.
    """
    # Create agent directory if not exists:
    agent_dir_path = f"./{application.get('aid')}"
    if not os.path.exists(agent_dir_path):
        os.mkdir(agent_dir_path)

    # Dump application material in json format:
    with open(agent_dir_path+"/agent.json", "w") as f:
        json.dump(application, f, indent=4)


if __name__ == "__main__":

    # Parse the arguments:
    import argparse
    import yaml
    import shutil
    parser = argparse.ArgumentParser(description="SAGA User Client CLI")
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode', default=False)
    parser.add_argument('--uconfig', type=str, help='Path to the user configuration .yml file')
    parser.add_argument('--register', action='store_true', help='Register a new user', default=False)
    parser.add_argument('--login', action='store_true', help='Login with existing user', default=False)
    parser.add_argument('--register-agents', action='store_true', help='Register agents for the user', default=False)


    args = parser.parse_args()
    if args.interactive:
        logger.log("CLI", "Running in interactive mode...")
        while True:
            print("\033[1m======= SAGA User Client CLI =======\033[0m")
            print("\033[1;34m1. Register\033[0m")
            print("\033[1;32m2. Login\033[0m")
            print("\033[1;33m3. Register Agent\033[0m")
            print("\033[1;31m4. Exit\033[0m")
            choice = input("Choose an option: ")

            if choice == '1':
                register()
            elif choice == '2':
                login()
            elif choice == '3':
                register_agent()
            elif choice == '4':
                print("Exiting...")
                exit(0)
    else:
        # Print a line of '=' as wide as the terminal window
        terminal_width = shutil.get_terminal_size().columns
        print("=" * terminal_width)
        logger.log("CLI", "Running in non-interactive mode...")

        # load the yml file:
        if args.uconfig:
            logger.log("CLI", f"Loading user configuration from \033[1m{args.uconfig}\033[0m...")
            with open(args.uconfig, 'r') as file:
                user_config = yaml.safe_load(file)
        else:
            raise ValueError("User configuration file not provided.")        


        if args.register:
            logger.log("CLI", "Registering user...")
            register(
                email=user_config.get('email'),
                password=user_config.get('passwd')
            )
        
        if args.login:
            logger.log("CLI", "Logging in user...")
            login(
                email=user_config.get('email'),
                password=user_config.get('passwd')
            )
        
        if args.register_agents:
            # For agent in user_config.get('agents'):
            for agent in user_config.get('agents'):
                # First authenticate the user:
                logger.log("CLI", "Authenticating user...")
                # Authenticate the user:
                login(
                    email=user_config.get('email'),
                    password=user_config.get('passwd')
                )
                # Then register the agent:
                logger.log("CLI", "Registering agent...")
                register_agent(
                    name=agent.get('name'),
                    device=agent.get('endpoint').get('device_name'),
                    IP=agent.get('endpoint').get('ip'),
                    port=agent.get('endpoint').get('port'),
                    num_one_time_keys=agent.get('num_one_time_keys'),
                    contact_rulebook=agent.get('contact_rulebook'),
                    a2a_card=agent.get('a2a_card')
                )
    

