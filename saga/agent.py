"""
    Agent class for the SAGA system.
"""
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
from pathlib import Path
from cryptography.x509 import Certificate

import saga.config
from saga.common.logger import Logger as logger
from saga.common.overhead import Monitor
from saga.common.contact_policy import check_rulebook, match
from saga.ca.CA import get_SAGA_CA
import saga.common.crypto as sc
from saga.local_agent import LocalAgent, DummyAgent

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
)
from typing_extensions import override

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.utils import new_agent_text_message

import asyncio
from typing import Any
from uuid import uuid4
import httpx
import uvicorn

from a2a.client import A2ACardResolver, A2AClient
from a2a.types import (MessageSendParams, SendMessageRequest,
                       SendStreamingMessageRequest)



DEBUG = False
NONCE_SIZE_BYTES = 12  # Size of the nonce in bytes
MAX_QUERIES = 100
# TODO: Handle max_queries

class HelloWorldAgent:
    """Hello World Agent."""

    async def invoke(self) -> str:
        return 'Hello World'

class HelloWorldAgentExecutor(AgentExecutor):
    """Test AgentProxy Implementation."""

    def __init__(self):
        self.agent = HelloWorldAgent()

    @override
    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        result = await self.agent.invoke()
        event_queue.enqueue_event(new_agent_text_message(result))

    @override
    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        raise Exception('cancel not supported')

class SAGAAgentExecutor(AgentExecutor):
    """SAGA Agent Executor."""

    def __init__(self, local_agent):
        self.local_agent = local_agent
        self.agent_instance = None
        self.initiating_agent = True

    @override
    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        query = context.get_user_input()
        self.agent_instance, result = self.local_agent.run(query, initiating_agent=self.initiating_agent, agent_instance=self.agent_instance)
        event_queue.enqueue_event(new_agent_text_message(result))

    @override
    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        raise Exception('cancel not supported')


def get_agent_material(dir_path: Path) -> dict:
    """
    Reads the agent material from the agent.json file in the given directory.

    Args:
        dir_path (Path): The directory path where the agent.json file is located.
    Returns:
        dict: The material read from the agent.json file.
    """
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


def serialize(obj):
    """
    Serializes the object to a JSON string.

    Args:
        obj: The object to serialize. It can be a bytes, list, dict, or any other type.
    """
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')
    elif isinstance(obj, list):
        return [serialize(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: serialize(value) for key, value in obj.items()}
    else:
        return obj


def deserialize(obj):
    """
    Deserializes the object from a JSON string.

    Args:
        obj: The object to deserialize. It can be a base64 encoded string, list, dict, or any other type.
    """
    if isinstance(obj, str):
        try:
            return base64.b64decode(obj)
        except:
            return obj
    elif isinstance(obj, list):
        return [deserialize(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: deserialize(value) for key, value in obj.items()}
    else:
        return obj


class Agent:
    """
        Main agent wrapper class for the SAGA system.
        This class is responsible for managing the agent's lifecycle, handling communication with other agents,
        and managing the agent's access control and security features.
    """
    def __init__(self, workdir: str, material: dict, local_agent: LocalAgent = None, a2a_port: int = None):
        """
        Initializes the Agent object with the given work directory and material.

        Args:
            workdir (str): The working directory for the agent.
            material (dict): The material for the agent, which contains the agent's credentials and other information.
            local_agent (LocalAgent): An optional local agent object that will be used to run tasks. If not provided, a DummyAgent will be used.
        """

        self.workdir = workdir
        if self.workdir[-1] != '/':
            self.workdir += '/'

        # library-agnostic agent object
        self.local_agent = local_agent
        if local_agent is None:
            logger.warn("No local agent provided. Using dummy agent.")
            self.local_agent = DummyAgent()
        
        # Check if local_agent is a child of LocalAgent:
        if not isinstance(self.local_agent, LocalAgent):
            raise Exception("Please provide a valid LocalAgent instance or a child of it.")

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
        if not check_rulebook(self.contact_rulebook):
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

        # Get the stamp issued by the provider (allegedly):
        agent_sig_bytes = material.get("agent_sig")
        self.stamp = material.get("stamp")
        self.card = {
            "aid": self.aid,
            "device": self.device,
            "IP": self.IP,
            "port": self.port,
            "agent_cert": base64.b64decode(material.get("agent_cert")),
            "pac":  base64.b64decode(material.get("pac")),
            "agent_sig": base64.b64decode(agent_sig_bytes),
        }
        # Verify the stamp:
        try:
            self.PK_Prov.verify(
                base64.b64decode(self.stamp),
                str(self.card).encode("utf-8")
            )
        except:
            logger.error("ERROR: PROVIDER STAMP VERIFICATION FAILED. UNSAFE CONNECTION.")
            raise Exception("ERROR: PROVIDER STAMP VERIFICATION FAILED. UNSAFE CONNECTION.")
        
        # Serialize the card:
        self.card['agent_cert'] = base64.b64encode(
            self.card['agent_cert']
        ).decode("utf-8")
        self.card['pac'] = base64.b64encode(
            self.card['pac']
        ).decode("utf-8")
        self.card['agent_sig'] = base64.b64encode(
            self.card['agent_sig']
        ).decode("utf-8")

        self.crt_u = sc.bytesToX509Certificate(
            base64.b64decode(material.get("crt_u"))
        )
        # Verify usr certificate:
        self.CA.verify(self.crt_u)

        self.monitor = Monitor()
        self.llm_monitor = Monitor(time.time)

        # A2A
        self.a2a_port = a2a_port
        self.rcv_a2a_card = None

    async def fetch_A2A_agent_card(self, base_url: str) -> AgentCard:
        """
        Fetches the A2A agent card from the given base URL.
        
        Args:
            base_url (str): The base URL of the A2A server.
        
        Returns:
            AgentCard: The fetched agent card.
        """
        PUBLIC_AGENT_CARD_PATH = "/.well-known/agent.json"
        logger.log("A2A_CLIENT", f"Attempting to fetch public agent card from: {base_url}{PUBLIC_AGENT_CARD_PATH}")
        async with httpx.AsyncClient() as httpx_client:
            resolver = A2ACardResolver(
                httpx_client=httpx_client,
                base_url=base_url,
            )
            logger.log("A2A_CLIENT", f"Resolver initialized with base URL: {resolver.base_url}")
            return await resolver.get_agent_card(relative_card_path=PUBLIC_AGENT_CARD_PATH)

    async def test_A2A_client(self, message: str, card=None, url=None) -> None:
        """
        Tests the A2A client by contacting the A2A server and connecting to it.
        """

        async with httpx.AsyncClient() as httpx_client:
            if card:
                client = A2AClient(
                    httpx_client=httpx_client, agent_card=card
                )
            elif url:
                client = A2AClient(
                    httpx_client=httpx_client, url=url
                )
            else:
                raise ValueError("Either card or url must be provided to initialize the A2A client.")
            
            logger.log("A2A_CLIENT", f"Client initialized with agent card: {client.url}")
            send_message_payload: dict[str, Any] = {
                'message': {
                    'role': 'user',
                    'parts': [
                        {'kind': 'text', 'text': message}
                    ],
                    'messageId': uuid4().hex,
                },
            }
            request = SendMessageRequest(
                params=MessageSendParams(**send_message_payload)
            )

            response = await client.send_message(request)
            # print(response)
            return response.model_dump(mode='json', exclude_none=True)['result']['parts'][0]['text']

    def start_A2A_Server(self, port: int):
        """
        Starts the A2A server for the agent.
        """
        def run():
            logger.log("A2A_SERVER", "Starting A2A server...")
            skill = AgentSkill(
                id='hello_world',
                name='Returns hello world',
                description='just returns hello world',
                tags=['hello world'],
                examples=['hi', 'hello world'],
            )

            # This will be the public-facing agent card
            public_agent_card = AgentCard(
                name='Hello World Agent',
                description='Just a hello world agent',
                url=f'http://localhost:{port}/',
                version='1.0.0',
                defaultInputModes=['text'],
                defaultOutputModes=['text'],
                capabilities=AgentCapabilities(streaming=True),
                skills=[skill],  # Only the basic skill for the public card
                supportsAuthenticatedExtendedCard=False,
            )

            # TODO: handle initiating/receiving agent flag within the SAGAAGentExecutor
            request_handler = DefaultRequestHandler(
                agent_executor=SAGAAgentExecutor(
                    local_agent=self.local_agent
                ),
                task_store=InMemoryTaskStore(),
            )

            app = A2AStarletteApplication(agent_card=public_agent_card,
                                            http_handler=request_handler)
        
            # uvicorn.run(app.build(), host='0.0.0.0', port=port)

            config = uvicorn.Config(app=app.build(), host="localhost", port=port, log_level="debug")
            server = uvicorn.Server(config=config)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(server.serve())
        
        # Start the A2A server in a separate thread
        a2a_server_thread = threading.Thread(target=run, daemon=True)
        a2a_server_thread.start()

    def get_provider_cert(self) -> Certificate:
        """
        This is a 'smarter' way to get the provider's certificate. This function uses the requests library
        to get the certificate of the server.
        
        Returns:
            cert (Certificate): The provider's certificate as a cryptography.x509.Certificate object.
        """
        provider_url = saga.config.PROVIDER_CONFIG['endpoint']
        response = requests.get(provider_url+"/certificate", verify=saga.config.CA_CERT_PATH, cert=(
            self.workdir+"agent.crt", self.workdir+"agent.key"
        ))
        cert_bytes = base64.b64decode(response.json().get('certificate'))
        cert = sc.bytesToX509Certificate(cert_bytes)
        
        return cert

    def lookup(self, t_aid: str) -> dict:
        """
        Looks up the target agent by its AID.
        This function sends a request to the provider to look up the target agent's AID.

        Args:
            t_aid (str): The AID of the target agent.
        Returns:
            data (dict): The data returned by the provider, which contains the target agent's information.
            If the access is denied, it returns None.
        """
        response = requests.post(f"{saga.config.PROVIDER_CONFIG['endpoint']}/lookup", json={'t_aid': t_aid}, verify=saga.config.CA_CERT_PATH, cert=(
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
        # TODO: How is this different from lookup()?
        response = requests.post(f"{saga.config.PROVIDER_CONFIG['endpoint']}/access", json={'i_aid':self.aid, 't_aid': t_aid}, verify=saga.config.CA_CERT_PATH, cert=(
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

    def generate_token(self, recipient_pac, sdhk) -> bytes:
        """
        Encode a token based on the shared diffie-hellman key.
        The token contains the following information:
        - Nonce: A random nonce for the token.
        - Issue Timestamp: The timestamp when the token was issued.
        - Expiration Timestamp: The timestamp when the token expires (1 hour from issue).
        - Communication Quota: The maximum number of communications allowed with this token.
        - Recipient PAC: The public access control key of the recipient agent.

        Args:
            recipient_pac: The public access control key of the recipient agent.
            sdhk: The shared Diffie-Hellman key used to encrypt the token.

        """
        # Generate a random nonce
        # TODO: Allow control of nonce length at some point
        nonce = os.urandom(NONCE_SIZE_BYTES)

        # Issue and expiration timestamps
        # TODO: Make sure we use UTC throughout the entire implementation
        issue_timestamp = datetime.now(tz=timezone.utc)
        # TODO: Allow control over the expiration-time over user's config
        expiration_timestamp = issue_timestamp + timedelta(hours=1)

        # Communication quota
        communication_quota = saga.config.Q_MAX  # Example quota

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

        Args:
            token (str): The token to check.
            recipient_pac: The public access control key of the recipient agent.
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

        Args:
            token (str): The token to check.
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

        Args:
            r_aid: The AID of the receiving agent.
            token_str: The string representation of the token.
            token_dict: The dictionary representation of the token.
        """
        with self.received_tokens_lock:
            self.received_tokens[token_str] = token_dict
            self.aid_to_token[r_aid] = token_str

    def retrieve_valid_token(self, r_aid):
        """
        Retrieves a valid token for the receiving agent.
        This function checks if the token is valid and if it is, returns it.
        If the token is not valid, it removes it from the received tokens and the aid_to_token dict.
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

    def send(self, conn, payload: dict):
        """
        Sends a JSON payload over the given connection.

        Args:
            conn: The connection to send the data over.
            payload (dict): The JSON payload to send. It should be a dictionary.
        """
        data = json.dumps(payload).encode('utf-8')
        conn.sendall(len(data).to_bytes(4, 'big') + data)

    def recv(self, conn) -> dict:
        """
        Receives a JSON payload from the given connection.

        Args:
            conn: The connection to receive the data from.
        
        Returns:
            response (dict): The JSON payload received from the connection.
            If the reception fails, it returns None.
        """
        try:
            length_bytes = conn.recv(4)
            length = int.from_bytes(length_bytes, 'big')

            buffer = b''
            while len(buffer) < length:
                buffer += conn.recv(length - len(buffer))

            response = json.loads(buffer.decode('utf-8'))
            return response
        except Exception as e:
            logger.error(f"Error receiving data: {e}")
            return None

    def initiate_conversation(self, conn, token: str, r_aid: str, init_msg: str) -> bool:
        """
        This function initiates a conversation with the receiving agent.
        It sends the initial message to the receiving agent and waits for a response.
        Returns true if the conversation ended from the initiating side.

        Args:
            conn: The connection to the receiving agent.
            token (str): The token that was received from the receiving agent.
            r_aid (str): The AID of the receiving agent.
            init_msg (str): The initial message to send to the receiving agent.
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
                self.monitor.stop("agent:communication_conv_init")
                return True

            # Send message:
            self.monitor.stop("agent:communication_conv_init")
            self.send(conn, msg)
            self.monitor.start("agent:communication_conv_init")
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
                self.monitor.stop("agent:communication_conv_init")
                return True
            # Receive response:
            self.monitor.stop("agent:communication_conv_init")
            response = self.recv(conn)
            self.monitor.start("agent:communication_conv_init")
            if not response:
                logger.warn("Failed to parse incoming socket message; connection may have closed abruptly during reception.")
                self.monitor.stop("agent:communication_conv_init")
                return False

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
                self.monitor.stop("agent:communication_conv_init")
                return False
            
            # Process message:
            if i > MAX_QUERIES:
                logger.warn("Maximum allowed number of queries in the conversation is reached. Ending conversation...")
                self.monitor.stop("agent:communication_conv_init")
                return True
            self.monitor.stop("agent:communication_conv_init")
            self.llm_monitor.start("agent:llm_backend_init")
            # PUSH DOWN THE A2A STACK:
            text = asyncio.run(self.test_A2A_client(received_message, url=f"http://localhost:{self.a2a_port}/"))
            logger.log("A2A_SERVER", f": replied '{text}'")
            # agent_instance, text = self.local_agent.run(received_message, initiating_agent=True, agent_instance=agent_instance)
            self.llm_monitor.stop("agent:llm_backend_init")
            self.monitor.start("agent:communication_conv_init")
            i += 1 # increment queries counter

    def receive_conversation(self, conn, token: str, recipient_pac) -> bool:
        """
        This function receives a conversation from the initiating agent.
        It waits for a message from the initiating agent and processes it.
        Returns true if the conversation ended from the receiving side.

        Args:
            conn: The connection to the initiating agent.
            token: The token that was received from the initiating agent.
            recipient_pac: The public access control key of the recipient agent.
        """
        agent_instance = None
        i = 0
        while True: 
            
            # Receive message from the initiating side:
            self.monitor.stop("agent:communication_conv_recv")
            message_dict = self.recv(conn)
            self.monitor.start("agent:communication_conv_recv")
            if not message_dict:
                logger.warn("Failed to parse incoming socket message; connection may have closed abruptly during reception.")
                self.monitor.stop("agent:communication_conv_recv")
                return False
            

            # Extract token from the message:
            token = message_dict.get("token", None)
            
            # Check if the token of the message is valid
            if not self.token_is_valid(token, recipient_pac):
                logger.error("Token is invalid. Ending conversation...")
                self.monitor.stop("agent:communication_conv_recv")
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
                self.monitor.stop("agent:communication_conv_recv")
                return False

            # Check if too many queries have been sent to your llm resources:
            if i > MAX_QUERIES:
                logger.warn("Maximum allowed number of queries in the conversation is reached. Ending conversation...")
                self.monitor.stop("agent:communication_conv_recv")
                return True

            # Get agent response:
            self.monitor.stop("agent:communication_conv_recv")
            self.llm_monitor.start("agent:llm_backend_recv")
            # PUSH DOWN THE A2A STACK:
            response = asyncio.run(self.test_A2A_client(received_message, url=f"http://localhost:{self.a2a_port}/"))
            logger.log("A2A_SERVER", f": replied '{response}'")
            # agent_instance, response = self.local_agent.run(query=received_message, initiating_agent=False, agent_instance=agent_instance)
            self.llm_monitor.stop("agent:llm_backend_recv")
            self.monitor.start("agent:communication_conv_recv")
            i+=1 # increase query counter
            
            # Prepare response:
            response_dict = {
                "msg": response,
                "token": token
            }
            # Send response:
            self.monitor.stop("agent:communication_conv_recv")
            self.send(conn, response_dict)
            self.monitor.start("agent:communication_conv_recv")
            logger.log("AGENT", f"Sent: \'{response_dict['msg']}\'")

            if response_dict['msg'] == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from receiving side.")
                # Invalidate the token:
                with self.active_tokens_lock:
                    # remove the token from the active tokens:
                    del self.active_tokens[token]
                    logger.log("ACCESS", "Token invalidated from the receiving side.")
                self.monitor.stop("agent:communication_conv_recv")
                return True

    def connect(self, r_aid, message: str):
        """
        Connects to the receiving agent and initiates a conversation with it.
        This function performs the following steps:
        1. Initializes the communication protocol with the receiving agent.
        2. Verifies the receiving agent's identity and device information.
        3. Creates a secure connection to the receiving agent.
        4. Initiates a conversation with the receiving agent.

        Args:
            r_aid: The AID of the receiving agent.
            message: The initial message to send to the receiving agent.
        """

        self.start_A2A_Server(self.a2a_port)

        # Test the A2A client:
        # result = asyncio.run(self.test_A2A_client("Hello World!"))
        # logger.log("A2A_CLIENT", f"Test A2A client result: {result}")
        self.rcv_a2a_card = asyncio.run(self.fetch_A2A_agent_card('http://localhost:9999'))
        logger.log("A2A_CLIENT", f"Fetched A2A agent card: {self.rcv_a2a_card}")
        
        # Start measuring algo overhead:
        self.monitor.start("agent:communication_proto_init")

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
            self.monitor.stop("agent:communication_proto_init")
            r_agent_material = self.access(r_aid)
            self.monitor.start("agent:communication_proto_init")

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

        # Stop measuring algo overhead:
        self.monitor.stop("agent:communication_proto_init")

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
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                with context.wrap_socket(sock, server_hostname=r_aid) as conn:
                    logger.log("NETWORK", f"Connected to {r_ip}:{r_port} with verified certificate.")

                    # Start measuring algo overhead:
                    self.monitor.start("agent:communication_proto_init")

                    # Prepare the request:
                    request_dict = {}
                    # Attach the agent's information card and the stamp from the Provider.
                    request_dict['crt_u'] = base64.b64encode(
                        self.crt_u.public_bytes(sc.serialization.Encoding.PEM)
                    ).decode("utf-8")
                    
                    request_dict['card'] = self.card                    
                    request_dict['stamp'] = self.stamp

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
                    # Stop the stopwatch
                    self.monitor.stop("agent:communication_proto_init")

                    # Send JSON request
                    self.send(conn, request_dict)

                    # Receive response
                    response_dict = self.recv(conn)

                    # Restart the stopwatch:
                    self.monitor.start("agent:communication_proto_init")
                    
                    if token is None and response_dict:
                        # If no valid token was found, the expected response is a token.
                        
                        self.monitor.start("agent:token_init")
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
                        self.monitor.stop("agent:token_init")
                        logger.log("OVERHEAD", f"agent:token_init: {self.monitor.elapsed('agent:token_init')}")
                        # Stop the stopwatch:
                        self.monitor.stop("agent:communication_proto_init")
                        logger.log("OVERHEAD", f"agent:communication_proto_init: {self.monitor.elapsed('agent:communication_proto_init')}")

                        # Start the conversation:
                        self.initiate_conversation(conn, new_enc_token_str, r_aid, message)
                        logger.log("OVERHEAD", f"agent:communication_conv_init: {self.monitor.elapsed('agent:communication_conv_init')}")
                        logger.log("OVERHEAD", f"agent:llm_backend_init: {self.llm_monitor.elapsed('agent:llm_backend_init')}")
                    else:
                        logger.log("ACCESS", f"Valid token found. Will start conversation.")
                        # If a valid token was found, the expected response is a message.
                        if response_dict:
                            if response_dict["token"] is not None:
                                # Stop the stopwatch:
                                self.monitor.stop("agent:communication_proto_init")
                                logger.log("OVERHEAD", f"agent:communication_proto_init: {self.monitor.elapsed('agent:communication_proto_init')}")
                                self.initiate_conversation(conn, token, r_aid, message)
                                logger.log("OVERHEAD", f"agent:communication_conv_init: {self.monitor.elapsed('agent:communication_conv_init')}")
                                logger.log("OVERHEAD", f"agent:llm_backend_init: {self.llm_monitor.elapsed('agent:llm_backend_init')}")
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

    def handle_i_agent_connection(self, conn, fromaddr):
        """
        Handles an incoming TLS connection from an initiating agent.

        This function performs the following steps:
        1. Receives the initial message from the initiating agent.
        2. Verifies the initiating agent's identity and device information.
        3. Checks access control rules to ensure the initiating agent is allowed to contact this agent.
        4. Verifies the initiating agent's user certificate and PAC.
        5. If all checks pass, it initiates a conversation with the initiating agent.

        Args:
            conn: The connection object for the incoming connection.
            fromaddr: The address of the initiating agent.
        """
        try:
            logger.log("NETWORK", f"Incoming connection from {fromaddr}.")

            # Receive data
            received_msg = self.recv(conn)
            if received_msg:
                    # Start the stopwatch:
                    self.monitor.start("agent:communication_proto_recv")
                    try:

                        # Extract i_aid from card:
                        i_card = received_msg.get("card", None)
                        #i_card = self.deserialize(i_card)
                        i_aid = i_card.get("aid", None)

                        # Check that the agent 

                        if i_aid is None:
                            logger.error("No agent ID found in the initial message from the initiating side.")
                            raise Exception("No agent ID provided.")
                        
                        if match(self.contact_rulebook, i_aid) < 0:
                            # The initiating agent is not allowed to contact the receiving agent.
                            logger.log("ACCESS", f"Access control failed: {i_aid} is not allowed to contact this agent.")
                            raise Exception(f"Access control failed: {i_aid} is not allowed to contact this agent.")
                        
                        # Fill in the agent certificate and agent IP from the connection:
                        # - this handles mismatch checks too
                        i_card['IP'] = fromaddr[0]
                        i_card['agent_cert'] = sc.der_to_pem(conn.getpeercert(binary_form=True))
                        # Convert to byte format for signature verification:
                        i_card['pac'] = base64.b64decode(i_card['pac'])
                        i_card['agent_sig'] = base64.b64decode(i_card['agent_sig'])
                
                        
                        logger.log("CRYPTO", f"Verifying {i_aid}'s stamp from the Provider.")
                        i_stamp = received_msg.get("stamp", None)
                        try:
                            self.PK_Prov.verify(
                                base64.b64decode(i_stamp),
                                str(i_card).encode("utf-8")
                            )
                        except:
                            logger.error(f"ERROR: {i_aid} STAMP VERIFICATION FAILED. UNSAFE CONNECTION.")
                            raise Exception(f"ERROR: {i_aid} STAMP VERIFICATION FAILED. UNSAFE CONNECTION.")
                        
                        # Check data integrity:
                        i_agent_material = i_card

                        # Perform verification checks:                                
                        if i_agent_material is None:
                            logger.error(f"{i_aid} not found.")
                            raise Exception(f"{i_aid} not found.")
                    
                        # Verify user certificate:
                        i_agent_user_cert_bytes = base64.b64decode(received_msg.get("crt_u", None))
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
                        i_agent_sig_bytes = i_agent_material.get("agent_sig")
                        logger.log("CRYPTO", f"Verifying {i_aid}'s signature.")
                        try:
                            pk_u.verify(
                                i_agent_sig_bytes,
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
                            self.monitor.start("agent:token_recv")
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
                            token_response = {"token": enc_token_str}
                            logger.log("ACCESS", f"Generated token: {enc_token_str}")

                            ser_token_response = json.dumps(token_response).encode('utf-8')
                            
                            # Store the token:
                            with self.active_tokens_lock:
                                self.active_tokens[enc_token_str] = sc.decrypt_token(enc_token_str, SDHK)

                            self.monitor.stop("agent:token_recv")
                            logger.log("OVERHEAD", f"agent:token_recv: {self.monitor.elapsed('agent:token_recv')}")
                            # Stop the stopwatch
                            self.monitor.stop("agent:communication_proto_recv")
                            logger.log("OVERHEAD", f"agent:communication_proto_recv: {self.monitor.elapsed('agent:communication_proto_recv')}")

                            self.send(conn, token_response)

                            # Start the conversation:
                            logger.log("AGENT", f"Starting conversation with {i_aid}.")
                            self.receive_conversation(conn, enc_token_str, i_pac)
                            logger.log("OVERHEAD", f"agent:communication_conv_recv: {self.monitor.elapsed('agent:communication_conv_recv')}")
                            logger.log("OVERHEAD", f"agent:llm_backend_recv: {self.llm_monitor.elapsed('agent:llm_backend_recv')}")
                        else:
                            # Check the token and see if it is in the active tokens:
                            if self.token_is_valid(i_token, i_pac):
                                # Stop the stopwatch
                                self.monitor.stop("agent:communication_proto_recv")
                                logger.log("OVERHEAD", f"agent:communication_proto_recv: {self.monitor.elapsed('agent:communication_proto_recv')}")

                                # If the token is valid, start the conversation:
                                logger.log("ACCESS", f"Valid token found. Will accept conversation.")
                                self.send(conn, {"token": i_token})
                                self.receive_conversation(conn, i_token, i_pac)
                                logger.log("OVERHEAD", f"agent:communication_conv_recv: {self.monitor.elapsed('agent:communication_conv_recv')}")
                                logger.log("OVERHEAD", f"agent:llm_backend_recv: {self.llm_monitor.elapsed('agent:llm_backend_recv')}")
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
        self.start_A2A_Server(self.a2a_port)
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
