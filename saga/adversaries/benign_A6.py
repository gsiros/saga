import fnmatch
import threading
import time
import json
import os
import bson.json_util
import socket
import ssl
import base64
import requests
from datetime import datetime, timedelta, timezone
import traceback
import saga.config
from pathlib import Path
import random
from saga.common.logger import Logger as logger
from saga.ca.CA import get_SAGA_CA

DEBUG = False
MAX_BUFFER_SIZE = 4096
MAX_QUERIES = 50
""""

Agent class for the SAGA system.

"""
import saga.common.crypto as sc

def get_agent_material(dir_path: Path):
    # Check if dir exists:
    if not os.path.exists(dir_path):
        os.mkdir(dir_path)

    # Open agent.json
    if dir_path[-1] != '/':
        dir_path += "/"

    material = None
    with open(dir_path+"agent.json", "r") as f:
        material = json.load(f)
    
    return material


class DummyAgent:
    """
    Dummy agent for networkig testing purposes. Simulates a dumb agent that thinks and returns a ranom response.
    """
    vocab = [
        "Hi",
        "Hello",
        "Yeah this makes sense.",
        "I think I understand.",
        "I love apples",
        "I don't know.",
        "I'm not sure.",
        "I'm sorry, I don't understand.",
        "I'm sorry, I can't do that.",
        "Do you think that we have purpose?",
        "What is the meaning of life?",
        "Do you think we are alone in the universe?",
        "I think we are alone in the universe.",
        "I think we are not alone in the universe.",
        'Faxxx',
        "<TASK_FINISHED>",
        "<TASK_FINISHED>",
        "<TASK_FINISHED>",
        "<TASK_FINISHED>"
    ]

    def __init__(self):
        self.task_finished_token = "<TASK_FINISHED>"

    def run(self, query, initiating_agent=None, agent_instance=None):
        time.sleep(1)
        if query == self.task_finished_token:
            return self.task_finished_token
        return None, random.choice(DummyAgent.vocab)


class Agent:
    def __init__(self, workdir, material, local_agent = None):

        self.workdir = workdir
        if self.workdir[-1] != '/':
            self.workdir += '/'

        # library-agnostic agent object
        self.local_agent = local_agent
        if local_agent is None:
            logger.warn("No local agent provided. Using dummy agent.")
            self.local_agent = DummyAgent()

        self.task_finished_token = self.local_agent.task_finished_token

        self.aid = material.get("aid")
        self.device = material.get("device")
        self.IP = material.get("IP")
        self.port = material.get("port")

        # TLS signing keys for the Agent:
        self.sk_a = sc.bytesToPrivateEd25519Key(
            base64.b64decode(material.get("secret_signing_key"))
        )

        # Load the agent's certificates
        self.cert = sc.bytesToX509Certificate(
            base64.b64decode(material.get("agent_cert"))
        )

        self.pk_a = self.cert.public_key()

        # Save the key and certificate:
        sc.save_ed25519_keys(self.workdir+"agent", self.sk_a, self.pk_a)
        sc.save_x509_certificate(self.workdir+"agent", self.cert)

        # Agent Access Control Key Pair:
        self.pac = sc.bytesToPublicX25519Key(
            base64.b64decode(material.get("pac"))
        )
        self.sac = sc.bytesToPrivateX25519Key(
            base64.b64decode(material.get("sac"))
        )
        

        # One-Time Keys:
        self.sotks = [sc.bytesToPrivateX25519Key(
            base64.b64decode(sotk)
        ) for sotk in material.get("sotks")]
        self.otks = [sc.bytesToPublicX25519Key(
            base64.b64decode(otk)
        ) for otk in material.get("otks")]

        # Join the One-time keys:
        self.otks_lock = threading.Lock()
        self.otks_dict = {}
        for i in range(len(self.otks)):
            self.otks_dict[self.otks[i].public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw
            )] = self.sotks[i] 

        # Agent Contact Policy Rulebook:
        self.contact_rulebook = material.get("contact_rulebook", [])
        if not self.check_rulebook(self.contact_rulebook):
            logger.error("Contact rulebook is not valid. Exiting...")
            raise Exception("Contact rulebook is not valid. Exiting...")

        # Init token storing dicts:
        self.active_tokens = {} # Active tokens that were given to initiating agents from the agent.
        self.active_tokens_lock = threading.Lock()
        self.aid_to_token = {} # dict that maps the aid of a receiving agent to the token that was given from them.
        self.received_tokens = {} # Tokens that were received from the receiving agents.
        self.received_tokens_lock = threading.Lock()

        # Previously contacted agents:
        self.previously_contacted_agents = {}

        # Provider Identity
        # Setup the SAGA CA:
        self.CA = get_SAGA_CA()
        # Download provider certificate
        provider_cert = self.get_provider_cert()
        # Verify the provider certificate:
        self.CA.verify(provider_cert) # if the verification fails an exception will be raised.
        self.PK_Prov = provider_cert.public_key()

    def get_provider_cert(self):
        """
        This is a 'smarter' way to get the provider's certificate. This function uses the requests library
        to get the certificate of the server.
        """
        provider_url = saga.config.PROVIDER_URL
        response = requests.get(provider_url+"/certificate", verify=saga.config.CA_CERT_PATH, cert=(
            self.workdir+"agent.crt", self.workdir+"agent.key"
        ))
        cert_bytes = base64.b64decode(response.json().get('certificate'))
        cert = sc.bytesToX509Certificate(cert_bytes)
        
        return cert

    def lookup(self, t_aid):
        response = requests.post(f"{saga.config.PROVIDER_URL}/lookup", json={'t_aid': t_aid}, verify=saga.config.CA_CERT_PATH, cert=(
            self.workdir+"agent.crt", self.workdir+"agent.key"
        )) 
        if response.status_code == 200:
            data = response.json()
            # Convert extended-json dict to python dict:
            data = bson.json_util.loads(json.dumps(data))
            return data
        elif response.status_code == 403:
            logger.log("ACCESS", f"Access denied to {t_aid}.")
            print(response.json())
            return None        
        
    def access(self, t_aid):
        response = requests.post(f"{saga.config.PROVIDER_URL}/access", json={'i_aid':self.aid, 't_aid': t_aid}, verify=saga.config.CA_CERT_PATH, cert=(
            self.workdir+"agent.crt", self.workdir+"agent.key"
        )) 
        if response.status_code == 200:
            data = response.json()
            # Convert extended-json dict to python dict:
            data = bson.json_util.loads(json.dumps(data))
            return data
        elif response.status_code == 403:
            logger.log("ACCESS", f"Access denied to {t_aid}.")
            print(response.json())
            return None

    def export_token(self, path, enc_token: str):
        """
        Exports the token to a file.
        """
        with open(path, "w") as f:
            f.write(enc_token)

    def generate_token(self, recipient_pac, sdhk) -> bytes:
        """
        Encode a token based on the shared diffie-hellman key.
        """

        # Generate a random nonce
        nonce = os.urandom(12)

        # Issue and expiration timestamps
        issue_timestamp = datetime.now(tz=timezone.utc)
        expiration_timestamp = issue_timestamp + timedelta(hours=1)

        # Communication quota
        communication_quota = 5  # Example quota

        # Token dictionary
        token_dict = {
            "nonce": nonce,
            "issue_timestamp": issue_timestamp,
            "expiration_timestamp": expiration_timestamp,
            "communication_quota": communication_quota,
            "recipient_pac": recipient_pac
        }

        # Encrypt the token using the shared DH key (SDHK)
        encrypted_token = sc.encrypt_token(token_dict, sdhk)
        
        return encrypted_token

    def token_is_valid(self, token: str, recipient_pac) -> bool:
        """
        Checks if a token that was presented by an initiating agent is valid.
        - If it was not generated by self, it is invalid.
        - If it is expired, it is invalid.
        - If the communication quota is reached, it is invalid.
        """
        with self.active_tokens_lock:
            if token not in self.active_tokens.keys():
                logger.error("Token provided by initiating not found in given tokens.")
                return False
            # Check if the token is still valid:
            token_dict = self.active_tokens[token]
        
            # Check the expiration date
            expiration_date = token_dict.get("expiration_timestamp")
            expiration_timestamp = datetime.fromisoformat(expiration_date)        
            if datetime.now(tz=timezone.utc) > expiration_timestamp:
                logger.error("Token expired.")
                return False
            
            # Check the communication quota:
            remaining_quota = token_dict.get("communication_quota")
            if remaining_quota == 0:
                logger.error("Token's max quota has been exceeded.")
                return False

            # Check if the recipient access control key is the same as the one that was used to initiate the convo.
            token_recipient_pac = token_dict.get("recipient_pac")
            recipient_pac_to_bytes = base64.b64encode(
                recipient_pac.public_bytes(
                    encoding=sc.serialization.Encoding.Raw,
                    format=sc.serialization.PublicFormat.Raw
                )
            ).decode('utf-8')

            if token_recipient_pac != recipient_pac_to_bytes:
                logger.error("Token's recipient PAC does not match the one that the token was originally issued to.")
                return False

            return True

    def received_token_is_valid(self, token: str) -> bool:
        """
        Makes sure that the token that was received from the receiving agent is valid.
        - If it is expired, it is invalid.
        - If the communication quota is reached, it is invalid.
        """
        with self.received_tokens_lock:
            if token not in self.received_tokens.keys():
                logger.log("ACCESS", "Token provided by receiving agent not found in given tokens.")
                return False
            
            # Check if the token is still valid:
            token_dict = self.received_tokens[token]
            
            # Check the expiration date
            expiration_date = token_dict.get("expiration_timestamp")
            expiration_timestamp = datetime.fromisoformat(expiration_date)        
            if datetime.now(tz=timezone.utc) > expiration_timestamp:
                logger.log("ACCESS", "Token expired.")
                return False
            
            # Check the communication quota:
            remaining_quota = token_dict.get("communication_quota")
            if remaining_quota == 0:
                logger.log("ACCESS", "Token's max quota has been exceeded.")
                return False

            return True

    def store_received_token(self, r_aid, token_str, token_dict):
        """
        Stores the token that was received from the receiving agent.
        """
        with self.received_tokens_lock:
            self.received_tokens[token_str] = token_dict
            self.aid_to_token[r_aid] = token_str

    def retrieve_valid_token(self, r_aid):
        """
        Retrieves a valid token for the receiving agent.
        """
        with self.received_tokens_lock: # THIS CREATES A DEADLOCK
            token = self.aid_to_token.get(r_aid, None)
        if token is None:
            return None
        if not self.received_token_is_valid(token):
            with self.received_tokens_lock:
                # remove the token from the received tokens:
                del self.received_tokens[token]
                # remove the token from the aid_to_token dict:
                del self.aid_to_token[r_aid]
            return None
        return token

    def initiate_conversation(self, conn, token: str, r_aid: str, init_msg: str) -> bool:
        """
        Returns true if the conversation ended from the initiating side.
        """
        agent_instance = None

        text = init_msg
        i = 0
        while True:
            # Prepare message: 
            msg = {
                "msg": text,
                "token": token
            }
            # Check if the received token that you are using is valid:
            if not self.received_token_is_valid(msg["token"]):
                logger.error("Token is invalid. Ending conversation...")
                return True

            # Send message:
            conn.sendall(json.dumps(msg).encode('utf-8'))
            logger.log("AGENT", f"Sent: \'{msg['msg']}\'")

            # Reduce the remaining quota for the token:
            with self.received_tokens_lock:
                self.received_tokens[token]["communication_quota"] = max(0, self.received_tokens[token]["communication_quota"] - 1)
                logger.log('ACCESS', f'Remaining token quota: {self.received_tokens[token]["communication_quota"]}')

            if msg['msg'] == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from initiating side.")
                # Invalidate the token:
                with self.received_tokens_lock:
                    # remove the token from the received tokens:
                    del self.received_tokens[token]
                    # remove the token from the aid_to_token dict:
                    del self.aid_to_token[r_aid]
                    logger.log("ACCESS", "Token invalidated from the initiating side.")
                return True
            # Receive response:
            response = conn.recv(MAX_BUFFER_SIZE)
            if not response:
                logger.warn("Received b'' indicating that the connection might have been closed from the other side. Returning...")
                return False
            response = json.loads(response.decode('utf-8'))

            # Process response:
            received_message = str(response.get("msg", self.local_agent.task_finished_token))
            logger.log("AGENT", f"Received: \'{received_message}\'")
            if received_message == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from receiving side.")
                # Invalidate the token:
                with self.received_tokens_lock:
                    # remove the token from the received tokens:
                    del self.received_tokens[token]
                    # remove the token from the aid_to_token dict:
                    del self.aid_to_token[r_aid]
                    logger.log("ACCESS", "Token invalidated from the receiving side.")
                return False
            
            # Process message:
            if i > MAX_QUERIES:
                logger.warn("Maximum allowed number of queries in the conversation is reached. Ending conversation...")
                return True
            agent_instance, text = self.local_agent.run(received_message, initiating_agent=True, agent_instance=agent_instance)
            i += 1 # increment queries counter

    def receive_conversation(self, conn, token: str, recipient_pac) -> bool:
        """
        Returns true if the conversation ended from the receiving side.
        """
        agent_instance = None
        i = 0
        while True: 
            
            # Receive message from the initiating side:
            message = conn.recv(MAX_BUFFER_SIZE)
            if not message:
                logger.warn("Received b'' indicating that the connection might have been closed from the other side. Returning...")
                return False
            
            # If the message is not empty, process it:
            message_dict = json.loads(message.decode('utf-8'))

            # Extract token from the message:
            token = message_dict.get("token", None)
            
            # Check if the token of the message is valid
            if not self.token_is_valid(token, recipient_pac):
                logger.error("Token is invalid. Ending conversation...")
                return True
            
            # Reduce the remaining quota for the token:
            with self.active_tokens_lock:
                self.active_tokens[token]["communication_quota"] = max(0, self.active_tokens[token]["communication_quota"] - 1)
                logger.log('ACCESS', f'Remaining token quota: {self.active_tokens[token]["communication_quota"]}')
            
            # Process message:
            received_message = str(message_dict.get("msg", self.local_agent.task_finished_token))
            logger.log("AGENT", f"Received: \'{received_message}\'")

            if received_message == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from initiating side.")
                # Invalidate the token:
                with self.active_tokens_lock:
                    # remove the token from the active tokens:
                    del self.active_tokens[token]
                    logger.log("ACCESS", "Token invalidated from the initiating side.")
                return False

            # Check if too many queries have been sent to your llm resources:
            if i > MAX_QUERIES:
                logger.warn("Maximum allowed number of queries in the conversation is reached. Ending conversation...")
                return True

            # Get agent response:
            agent_instance, response = self.local_agent.run(query=received_message, initiating_agent=False, agent_instance=agent_instance)
            i+=1 # increase query counter
            
            # Prepare response:
            response_dict = {
                "msg": response,
                "token": token
            }
            # Send response:
            conn.sendall(json.dumps(response_dict).encode('utf-8'))
            logger.log("AGENT", f"Sent: \'{response_dict['msg']}\'")

            if response_dict['msg'] == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from receiving side.")
                # Invalidate the token:
                with self.active_tokens_lock:
                    # remove the token from the active tokens:
                    del self.active_tokens[token]
                    logger.log("ACCESS", "Token invalidated from the receiving side.")
                return True

    def connect(self, r_aid, message: str):

        # Get everything you need to reach the receiving agent from the provider:

        # Check if you have a token:
        logger.log("ACCESS", f"Checking if a token exists for {r_aid}.")
        token = self.retrieve_valid_token(r_aid)
        if token is not None:
            # Fetch agent information from memory:
            logger.log("ACCESS", f"Found token for {r_aid}. Will use it.")
            r_agent_material = self.previously_contacted_agents.get(r_aid, None)
        else:
            # Fetch agent information from the provider:
            logger.log("ACCESS", f"No valid token found for {r_aid}.")
            logger.log("ACCESS", f"Requesting access to {r_aid} via the Provider.")
            r_agent_material = self.access(r_aid)

        if r_agent_material is None:
            logger.log("ACCESS", f"Access to {r_aid} denied.")
            return

        # ========================================================================
        # Perform verification checks for integrity purposes before connecting to 
        # the receiving agent.
        # ========================================================================    

        # Verify user certificate:
        r_agent_user_cert_bytes = r_agent_material.get("crt_u", None)
        r_agent_user_cert = sc.bytesToX509Certificate(r_agent_user_cert_bytes)

        logger.log("CRYPTO", f"Verifying {r_aid}'s user certificate.")
        try:
            self.CA.verify(r_agent_user_cert)
        except:
            logger.error(f"ERROR: {r_aid} USER CERTIFICATE VERIFICATION FAILED. UNSAFE CONNECTION.")
            raise Exception(f"ERROR: {r_aid} USER CERTIFICATE VERIFICATION FAILED. UNSAFE CONNECTION.")

        # Retrieve user identity key: 
        pk_u = r_agent_user_cert.public_key()
    
        # Verify the agent's identity:
        r_aid = r_agent_material.get("aid", None)
        r_agent_cert_bytes = r_agent_material.get("agent_cert", None)
        r_agent_cert = sc.bytesToX509Certificate(
            r_agent_cert_bytes 
        )
        if r_agent_cert is None:
            logger.error("No valid certificate found.")
            raise Exception("No valid certificate found.")
        r_agent_pk = r_agent_cert.public_key()
        r_agent_pk_bytes = r_agent_pk.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw
        )        

        # Verify the target agent's device information:
        r_device = r_agent_material.get("device")
        r_ip = r_agent_material.get("IP")
        r_port = r_agent_material.get("port")

        dev_network_info = {
            "aid": r_aid, 
            "device": r_device, 
            "IP": r_ip, 
            "port": r_port
        }

        r_agent_pac_bytes = r_agent_material.get("pac", None)

        crypto_info = {
            "pk_a": r_agent_pk_bytes,
            "pac": r_agent_pac_bytes,
            "pk_prov": self.PK_Prov.public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw
            )
        }

        block = {}
        block.update(dev_network_info)
        block.update(crypto_info)
        r_agent_sig_bytes = r_agent_material.get("agent_sig")
        logger.log("CRYPTO", f"Verifying {r_aid}'s signature.")
        try:
            pk_u.verify(
                r_agent_sig_bytes,
                str(block).encode("utf-8")
            )
        except:
            logger.error(f"ERROR: {r_aid} SIGNATURE VERIFICATION FAILED. MATERIAL INTEGRITY PERHAPS COMPROMISED. UNSAFE CONNECTION.")
            return

        # ========================================================================
        # If no signature verification fails, that means that the receiving agent's 
        # information is legitimate. The initiating agent can request a connection 
        # to the receiving agent.
        # ========================================================================
        
        # Save/Update agent material in memory now that it is verified:
        self.previously_contacted_agents[r_aid] = r_agent_material

        # Create SSL context for the client
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2  # TLS 1.3 only
        # Load the self-signed certificate and private key
        context.load_cert_chain(certfile=self.workdir + "agent.crt", keyfile=self.workdir + "agent.key")
        # Load the CA certificate for verification:    
        context.load_verify_locations(saga.config.CA_CERT_PATH)


        try:
            # Create and connect the socket
            with socket.create_connection((r_ip, r_port)) as sock:
                with context.wrap_socket(sock, server_hostname=r_aid) as conn:
                    logger.log("NETWORK", f"Connected to {r_ip}:{r_port} with verified certificate.")

                    # Prepare the request:
                    request_dict = {}
                    request_dict['aid'] = self.aid # The initiating agent's ID

                    # If there is no active token for contacting r_aid:
                    if token is None:
                        # If no token is found, the initiating agent must 
                        # receive a new one from the receiving agent.
                        logger.log("ACCESS", f"Requesting new token from {r_aid}.")
                        # Use of the receiving agent's one-time keys:
                        r_otk = r_agent_material.get("one_time_keys", None)[0]
                        r_otk_sig_bytes = r_agent_material.get("one_time_key_sigs", None)[0]
                        
                        # Verify the one-time key:
                        try:
                            pk_u.verify(
                                r_otk_sig_bytes,
                                r_otk
                            )
                        except:
                            logger.error(f"ERROR: {r_aid} ONE TIME KEY VERIFICATION FAILED. UNSAFE CONNECTION.")
                            raise Exception(f"ERROR: {r_aid} ONE TIME KEY VERIFICATION FAILED. UNSAFE CONNECTION.")

                        # Prepare JSON message
                        request_dict['otk'] = base64.b64encode(r_otk).decode("utf-8")
                    else:
                        # If a token is found, the initiating agent can send 
                        # it to the receiving agent.                        
                        request_dict['token'] = token
                        
                    # Encode the request as JSON
                    request_json = json.dumps(request_dict).encode('utf-8')
                    # Send JSON request
                    conn.sendall(request_json)

                    # Receive response
                    response = conn.recv(MAX_BUFFER_SIZE)
                    if token is None and response:
                        # If no valid token was found, the expected response is a token.
                        response_dict = json.loads(response.decode('utf-8'))
                        
                        # Diffie hellman calculations:
                        r_otk = sc.bytesToPublicX25519Key(r_otk)
                        DH = self.sac.exchange(r_otk)

                        shared_secrets = [DH]
                        concat_secret = b''.join(shared_secrets)

                        SDHK = sc.HKDF(
                            algorithm=sc.hashes.SHA256(),
                            length=32,  # Generate a 256-bit key
                            salt=None,  # Optional: Provide a salt for added security
                            info=b"access-control-shdk-exchange",
                        ).derive(concat_secret)

                        logger.log("ACCESS", f"Derived SDHK: {SDHK.hex()}")

                        # Receive the new token:
                        # The new token that is generated will be received as a string.
                        # This string is an encoding, i.e. an encryption of the token's
                        # metadata.
                        new_enc_token_str = response_dict.get("token", None)
                        logger.log("ACCESS", f"Received token: {new_enc_token_str}")

                        # Decrypt the token:
                        token_dict = sc.decrypt_token(new_enc_token_str, SDHK)
                        # Store the token:
                        self.store_received_token(r_aid, new_enc_token_str, token_dict)
                        
                        # Start the conversation:
                        self.initiate_conversation(conn, new_enc_token_str, r_aid, message)         
                    else:
                        logger.log("ACCESS", f"Valid token found. Will start conversation.")
                        # If a valid token was found, the expected response is a message.
                        if response:
                            response_dict = json.loads(response.decode('utf-8'))
                            if response_dict["token"] is not None:
                                self.initiate_conversation(conn, token, r_aid, message)
                            else:
                                logger.error("Token rejected from receiving side.")
                                
        except ssl.SSLError as e:
            print(f"SSL Error: {e}")

        except Exception as e:
            print(f"Error: {e}")
            traceback.print_exc()

        finally:
            try:
                logger.log("NETWORK", "Attempting to close connection.")
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                logger.log("NETWORK", "Connection succesfully closed.")
            except:
                logger.log("NETWORK", "Connection already closed by other party.")

    def check_rulebook(self, rulebook):
        """
        Checks if the contact rulebook is valid.
        """
        if rulebook is None:
            return False
        for rule in rulebook:
            # Rules are in the form of:
            # alice@her_email.com:bobafet
            components = rule.split(":")
            if len(components) == 1:
                if components[0] != "*":
                    logger.error(f"Invalid AC rule {rule} format. Expected format: <aid> = <uid>:<name>")
                    return False
                continue
            if len(components) != 2:
                logger.error(f"Invalid AC rule {rule} format. Expected format: <aid> = <uid>:<name>")
                return False
            uid, name = components[0], components[1]
            if not isinstance(uid, str) or not isinstance(name, str):
                logger.error(f"Invalid AC rule {rule} format. Expected format: <aid> = <uid>:<name>. Both the uid and aid must be strings.")
                return False
        return True

    def check_aid(self, aid):
        """
        Checks if the AID is in the right format.
        """
        # AID is in the form of:
        # alice@her_email.com:bobafet
        components = aid.split(":")
        if len(components) != 2:
            logger.error("Invalid AID format. Expected format: <aid> = <uid>:<name>")
            return False
        uid, name = components[0], components[1]
        if not isinstance(uid, str) or not isinstance(name, str):
            logger.error("Invalid AID format. Expected format: <aid> = <uid>:<name>. Both the uid and aid must be strings.")
            return False
        # Check if the uid and name are valid:
        # The uid must only have 1 '@' character and NO ':' characters.
        if uid.count('@') != 1 or uid.count(':') != 0:
            logger.error("Invalid UID format.")
        # Check the name format:
        # The name must not have any ':' characters.
        if name.count(':') != 0:
            logger.error("Invalid NAME format.")
            return False
        return True

    def allowed_to_contact(self, i_aid):
        """
        Checks if the initiating agent is allowed to contact the receiving agent.
        If the
        """

        # Check that the i_aid is in the right format:
        if not self.check_aid(i_aid):
            logger.error("Invalid AID format. Expected format: <aid> = <uid>:<name>")
            return False
        
        # Check if the agent is allowed to contact the receiving agent:
        for rule in self.contact_rulebook:
            # Use fnmatch for Unix filename pattern matching
            if fnmatch.fnmatch(i_aid, rule):
                # The agent is allowed to contact the receiving agent.
                return True
        # Otherwise, the agent is not allowed to contact the receiving agent.
        return False

    def handle_i_agent_connection(self, conn, fromaddr):
        """
        Handles an incoming TLS connection from an intiating agent.
        """
        try:
            logger.log("NETWORK", f"Incoming connection from {fromaddr}.")

            # Receive data
            data = conn.recv(MAX_BUFFER_SIZE)
            if data:
                    try:
                        # Decode and parse JSON data
                        received_msg = json.loads(data.decode('utf-8'))

                        # Extract i_aid:
                        i_aid = received_msg.get("aid", None)

                        if i_aid is None:
                            logger.error("No agent ID found in the initial message from the initiating side.")
                            raise Exception("No agent ID provided.")
                        
                        if not self.allowed_to_contact(i_aid):
                            # The initiating agent is not allowed to contact the receiving agent.
                            logger.log("ACCESS", f"Access control failed: {i_aid} is not allowed to contact this agent.")
                            raise Exception(f"Access control failed: {i_aid} is not allowed to contact this agent.")

                        # Ask the provider for the details of the initiating agent:
                        logger.log("ACCESS", f"Fetching crypto and device information for {i_aid} from the Provider.")
                        i_agent_material = self.lookup(i_aid)

                        # Perform verification checks:                                
                        if i_agent_material is None:
                            logger.error(f"{i_aid} not found.")
                            raise Exception(f"{i_aid} not found.")
                    
                        # Verify user certificate:
                        i_agent_user_cert_bytes = i_agent_material.get("crt_u", None)
                        i_agent_user_cert = sc.bytesToX509Certificate(i_agent_user_cert_bytes)

                        logger.log("CRYPTO", f"Verifying {i_aid}'s user certificate.")
                        try:
                            self.CA.verify(i_agent_user_cert)
                        except:
                            logger.error(f"ERROR: {i_aid} USER CERTIFICATE VERIFICATION FAILED. UNSAFE CONNECTION.")
                            raise Exception(f"ERROR: {i_aid} USER CERTIFICATE VERIFICATION FAILED. UNSAFE CONNECTION.")

                        # Retrieve user identity key: 
                        pk_u = i_agent_user_cert.public_key()
                    
                        # Verify the agent's identity:
                        i_agent_cert = sc.bytesToX509Certificate(sc.der_to_pem(conn.getpeercert(binary_form=True)))
                        if i_agent_cert is None:
                            logger.error("No valid certificate found.")
                            raise Exception("No valid certificate found.")
                        
                        i_agent_pk = i_agent_cert.public_key()
                        i_agent_pk_bytes = i_agent_pk.public_bytes(
                            encoding=sc.serialization.Encoding.Raw,
                            format=sc.serialization.PublicFormat.Raw
                        )
                    
                        i_device = i_agent_material.get("device")
                        # Use the connections's IP to verify the device information.
                        i_ip = fromaddr[0]
                        i_port = i_agent_material.get("port")
                        dev_network_info = {
                            "aid": i_aid, 
                            "device": i_device, 
                            "IP": i_ip, 
                            "port": i_port
                        }

                        i_agent_pac_bytes = i_agent_material.get("pac", None)
                        i_pac = sc.bytesToPublicX25519Key(i_agent_pac_bytes)
                        crypto_info = {
                            "pk_a": i_agent_pk_bytes,
                            "pac": i_agent_pac_bytes,
                            "pk_prov": self.PK_Prov.public_bytes(
                                encoding=sc.serialization.Encoding.Raw,
                                format=sc.serialization.PublicFormat.Raw
                            )
                        }


                        block = {}
                        block.update(dev_network_info)
                        block.update(crypto_info)
                        r_agent_sig_bytes = i_agent_material.get("agent_sig")
                        logger.log("CRYPTO", f"Verifying {i_aid}'s signature.")
                        try:
                            pk_u.verify(
                                r_agent_sig_bytes,
                                str(block).encode("utf-8")
                            )
                        except:
                            logger.error(f"ERROR: {i_aid} SIGNATURE VERIFICATION FAILED. MATERIAL INTEGRITY PERHAPS COMPROMISED. UNSAFE CONNECTION.")
                            raise Exception(f"ERROR: {i_aid} SIGNATURE VERIFICATION FAILED. MATERIAL INTEGRITY PERHAPS COMPROMISED. UNSAFE CONNECTION.")

                        # ========================================================================
                        # If no signature verification fails, that means that the receiving agent's 
                        # information is legitimate. The initiating agent can request a connection 
                        # to the receiving agent.
                        # ========================================================================

                        # ============================ ACCESS CONTROL ============================

                        # Check if the initiating agent has a token:
                        i_token = received_msg.get("token", None)
                        if i_token is None:
                            # The initiating agent does not have a token. 
                            logger.log("ACCESS", f"No valid received token found. For {i_aid}. Generating new one.")
                            
                            # The agent must have a otk:
                            i_otk_json = received_msg.get("otk", None)
                            if i_otk_json is None:
                                logger.error("Acces control failed: no one-time key provided from initiating agent.")
                                raise Exception("Acces control failed: no one-time key provided from initiating agent.")
                            i_otk_bytes = base64.b64decode(i_otk_json)
                            
                            with self.otks_lock:
                                # Look for the otk-sotk pair in the otks struct:
                                if i_otk_bytes not in self.otks_dict.keys():
                                    logger.error("Access control failed: unknown one-time key.")
                                    raise Exception("Access control failed: unknown one-time key.")
                                sotk = self.otks_dict[i_otk_bytes]
                                # Remove the used one-time key to prevent replay attacks.
                                del self.otks_dict[i_otk_bytes]

                            # Diffie hellman calculations:
                            DH = sotk.exchange(i_pac)
                            
                            shared_secrets = [DH]
                            concat_secret = b''.join(shared_secrets)

                            SDHK = sc.HKDF(
                                algorithm=sc.hashes.SHA256(),
                                length=32,  # Generate a 256-bit key
                                salt=None,  # Optional: Provide a salt for added security
                                info=b"access-control-shdk-exchange",
                            ).derive(concat_secret)

                            logger.log("ACCESS", f"Derived SDHK: {SDHK.hex()}")
                            
                            # Generate the token:
                            enc_token_bytes = self.generate_token(i_pac, SDHK)
                            enc_token_str = base64.b64encode(enc_token_bytes).decode('utf-8')

                            self.export_token(saga.config.AGENT_MOM_WORKDIR+"/notmy.token", enc_token_str)
                            # Store the token:
                            with self.active_tokens_lock:
                                self.active_tokens[enc_token_str] = sc.decrypt_token(enc_token_str, SDHK)
                            logger.log("BENIGN", f"Token {enc_token_str} exported to notmy.token")
                            raise Exception("Token exported to notmy.token")

                            token_response = {"token": enc_token_str}
                            logger.log("ACCESS", f"Generated token: {enc_token_str}")

                            ser_token_response = json.dumps(token_response).encode('utf-8')
                            
                            # Store the token:
                            with self.active_tokens_lock:
                                self.active_tokens[enc_token_str] = sc.decrypt_token(enc_token_str, SDHK)

                            conn.sendall(ser_token_response)

                            # Start the conversation:
                            logger.log("AGENT", f"Starting conversation with {i_aid}.")
                            self.receive_conversation(conn, enc_token_str, i_pac)
                        else:
                            # Check the token and see if it is in the active tokens:
                            if self.token_is_valid(i_token, i_pac):
                                # If the token is valid, start the conversation:
                                logger.log("ACCESS", f"Valid token found. Will accept conversation.")
                                conn.sendall(json.dumps({"token": i_token}).encode('utf-8'))
                                self.receive_conversation(conn, i_token, i_pac)
                            else:
                                logger.error("Token is invalid. Ending connection.")

                    except json.JSONDecodeError:
                        print("Received invalid JSON format.")


                    except Exception as e:
                        print(f"Error: {e}")
                        traceback.print_exc()
        finally:
            try:
                logger.log("NETWORK", "Attempting to close connection.")
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                logger.log("NETWORK", "Connection succesfully closed.")
            except:
                logger.log("NETWORK", "Connection already closed by other party.")

    def listen(self):
        """
        Listens for incoming TLS connections, handles Ctrl+C gracefully,
        and ensures proper socket closure on shutdown.
        """
        # Create SSL context for the server
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2  # TLS 1.3 only
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(saga.config.CA_CERT_PATH)
        # Load the self-signed certificate and private key
        context.load_cert_chain(certfile=self.workdir + "agent.crt", keyfile=self.workdir + "agent.key")

        # Create and bind the socket
        bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bindsocket.bind((self.IP, int(self.port)))
        bindsocket.listen(5)

        logger.log("NETWORK", f"Listening on {self.IP}:{self.port}... (Press Ctrl+C to stop)")

        try:
            while True:
                try:
                    # Incoming connection:
                    newsocket, fromaddr = bindsocket.accept()
                    # TLS takes over and tries to
                    conn = context.wrap_socket(newsocket, server_side=True)
                    logger.log("NETWORK", f"Connection from {fromaddr}")
                    # Spawn a new thread to handle the incoming connection:
                    i_agent_thread = threading.Thread(target=self.handle_i_agent_connection, args=(conn, fromaddr))
                    i_agent_thread.daemon = True  # Daemon mode: Exits when main thread ends
                    i_agent_thread.start()

                except KeyboardInterrupt:
                    print("\nReceived Ctrl+C, shutting down server gracefully...")
                    break

                except ssl.SSLError as e:
                    logger.error(f"SSL Error: {e}")
        finally:
            bindsocket.close()
            print("Server socket closed. Exiting.")

if __name__ == "__main__":
    import saga.config
    import json

    agent_manifest_path = saga.config.AGENT_GEORGE_WORKDIR + "/agent.json"
    agent_manifest = None
    with open(agent_manifest_path, 'r') as file:
        agent_manifest = json.load(file)
    dummy_agent = Agent(saga.config.AGENT_GEORGE_WORKDIR, agent_manifest)
    dummy_agent.listen()
