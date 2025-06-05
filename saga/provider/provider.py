"""
    Provider for SAGA agents that handles user registration, authentication, and certificate management.
"""
import ssl
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, JWTManager
from flask_pymongo import PyMongo
import base64
from datetime import datetime, timezone, timedelta
import os

import saga.common.crypto as sc
from saga.ca.CA import get_SAGA_CA
import saga.config
from saga.common.logger import Logger as logger
from saga.common.overhead import Monitor
from saga.common.contact_policy import check_rulebook, check_aid, match

class Provider:
    """
    Provider class for SAGA agents.
    """
    def __init__(
            self,
            workdir,
            name: str,
            host: str="0.0.0.0", 
            port: int=5000, 
            mongo_uri: str="mongodb://localhost:27017/saga", 
            jwt_secret: str="supersecretkey"
        ):
        """
        Initializes the Provider with MongoDB, JWT, and OAuth configuration.

        Args:
            workdir: Directory where the provider will store its data.
            name (str): Name of the provider.
            host (str): Host address for the Flask app.
            port (int): Port for the Flask app.
            mongo_uri (str): MongoDB URI for the provider's database.
            jwt_secret (str): Secret key for JWT authentication.
        """

        self.workdir = workdir if workdir[-1] == '/' else workdir+'/'
        if not os.path.exists(self.workdir):
            os.mkdir(self.workdir)
        self.name = name
        self.app = Flask(__name__)
        self.app.config["MONGO_URI"] = mongo_uri
        self.app.config["JWT_SECRET_KEY"] = jwt_secret

        # Initialize MongoDB, JWT, and Bcrypt
        self.mongo = PyMongo(self.app)
        self.jwt = JWTManager(self.app)
        self.bcrypt = Bcrypt(self.app)

        self.active_jwt_tokens = []

        # MongoDB Collections
        self.users_collection = self.mongo.db.users
        self.agents_collection = self.mongo.db.agents

        # Load CA object for certificate signing:
        self.CA = get_SAGA_CA()

        # Load TLS signing keys:
        if not (os.path.exists(self.workdir+f"{self.name}.key") and os.path.exists(self.workdir+f"{self.name}.pub") and os.path.exists(self.workdir+f"{self.name}.crt")):
            # Generate cryptographic material for signing. 
            self.SK_Prov, self.PK_Prov = sc.generate_ed25519_keypair()
            self.cert = self.CA.sign(self.PK_Prov, config=saga.config.PROVIDER_CONFIG['config'])
            sc.save_ed25519_keys(self.workdir+f"{self.name}", self.SK_Prov, self.PK_Prov)
            sc.save_x509_certificate(self.workdir+f"{self.name}", self.cert)
        else:
            self.SK_Prov, self.PK_Prov = sc.load_ed25519_keys(self.workdir+f"{self.name}")
            self.cert = sc.load_x509_certificate(self.workdir+f"{self.name}.crt")
        self.ssl_context = (self.workdir+f"{self.name}.crt", self.workdir+f"{self.name}.key")

        # Register routes
        self._register_routes()

        # Web server settings
        self.host = host
        self.port = port

        self.monitor = Monitor()

    def _register_routes(self):
        """Registers all Flask routes for the provider."""

        @self.app.route('/')
        def index():
            return "<h1>Hello, World!</h1>"

        @self.app.route('/certificate', methods=['GET'])
        def certificate():
            return jsonify({"certificate": base64.b64encode(self.cert.public_bytes(
                sc.serialization.Encoding.PEM
            )).decode("utf-8")}), 200

        @self.app.route('/register', methods=['POST'])
        def register():
            """
            This endpoint is used by the user to register with the provider. The user must
            provide their desired UID (public) and password (private). The user must also 
            provide their public identity key for signing. 
            """
            self.monitor.start("provider:user_register")
            # Retrieve the user's uid and password from the request body.
            data = request.json
            uid = data.get("uid")
            password = data.get("password")

            if self.users_collection.find_one({"uid": uid}):
                logger.error(f"User {uid} already exists.")
                return jsonify({"message": "User already exists"}), 400

            # Store password hash and identity key in the database.
            hashed_pw = self.bcrypt.generate_password_hash(password).decode("utf-8")
            # Get the user certificate:
            crt_u_bytes = base64.b64decode(data.get("crt_u"))
            crt_u = sc.bytesToX509Certificate(crt_u_bytes)
            # Verify the user's certificate:
            try:
                self.CA.verify(crt_u)
            except:
                logger.error(f"Invalid user certificate.")
                return jsonify({"message": "Invalid user certificate"}), 401

            self.users_collection.insert_one({
                "uid": uid,
                "password": hashed_pw,
                "crt_u": crt_u_bytes,
                "auth_tokens": []
            })

            self.monitor.stop("provider:user_register")
            logger.log("OVERHEAD", f"provider:user_register: {self.monitor.elapsed('provider:user_register')}")
            return jsonify({"message": "User registered successfully"}), 201

        @self.app.route('/login', methods=['POST'])
        def login():
            """
            This endpoint is used by the user to login. The user must provide their UID
            and password in the request body. If the credentials are valid, the user will
            receive an access token that can be used to authenticate future requests.

            The access token is valid for 24 hours.
            """
            # Retrieve the user's uid and password from the request body.
            self.monitor.start("provider:user_login")
            data = request.json
            uid = data.get("uid")
            password = data.get("password")

            # Check if the user exists and the password is correct.
            user = self.users_collection.find_one({"uid": uid})
            if user and self.bcrypt.check_password_hash(user["password"], password):
                access_token = create_access_token(identity=user["uid"])
                self.users_collection.update_one({"uid": uid}, {"$push": {"auth_tokens": {
                    "token": access_token,
                    "exp": (datetime.now(timezone.utc) + timedelta(days=1)).replace(tzinfo=timezone.utc)
                }}})
                logger.log("PROVIDER", f"User {uid} logged in successfully.")
                self.monitor.stop("provider:user_login")
                logger.log("OVERHEAD", f"provider:user_login: {self.monitor.elapsed('provider:user_login')}")
                return jsonify({"access_token": access_token}), 200
            
            logger.error(f"Invalid credentials for user {uid}.")
            self.monitor.stop("provider:user_login")
            logger.log("OVERHEAD", f"provider:user_login: {self.monitor.elapsed('provider:user_login')}")
            return jsonify({"message": "Invalid credentials"}), 401

        @self.app.route('/register_agent', methods=['POST'])
        def register_agent():
            """
            This endpoint is used by the user to register a new agent. The user must provide
            the agent's cryptographic material, including the agent's public access control 
            key, public signing key, and one-time keys. The user must also provide
            the agent's device information, including the device name, IP address, and port.

            The user must also provide the agent's certificate, signed by a CA. The user must
            also provide the signatures of the agent's information and cryptographic material,
            and the signatures of the one-time keys.

            The user MUST be authenticated to register an agent. The user must provide their
            UID and a valid JWT in the request body.

            """
            self.monitor.start("provider:agent_register")
            # Retrieve the user's uid and JWT from the request body.
            data = request.json
            uid = data.get("uid")
            user_jwt = data.get("jwt")

            # Validate user
            user = self.users_collection.find_one({"uid": uid})
            if not user:
                logger.error(f"User {uid} not found.")
                return jsonify({"message": "User not found"}), 404
            
            # Make sure that the user has been recently authenticated
            usr_record = self.users_collection.find_one({"uid": uid, "auth_tokens.token": user_jwt})
            if not usr_record:
                logger.error(f"User {uid} not authenticated.")
                return jsonify({"message": "User not authenticated"}), 401
            
            # Check that the authentication token is valid and not expired
            now = datetime.now(timezone.utc)
            exp = usr_record["auth_tokens"][0]["exp"].replace(tzinfo=timezone.utc)
            if now > exp:
                logger.error(f"User {uid} token expired.")
                return jsonify({"message": "Token expired."}), 401

            # ========================================================================
            # Start the agent registration processing. At this point, the provider 
            # collects all the relevant cryptographic material and verifies the
            # signatures provided by the user. 
            # ========================================================================

            # Extract the agent's given aid.
            application = data.get("application")
            aid = application.get("aid")
            if not aid:
                logger.error(f"Agent aid not provided.")
                return jsonify({"message": "Agent aid not provided"}), 400

            # Make sure that the aid is in the right format.
            if not check_aid(aid):
                logger.error(f"Invalid agent aid format.")
                return jsonify({"message": "Invalid agent aid format"}), 400
            
            # Reject if aid is already being used by another agent.
            if self.agents_collection.find_one({"aid": aid}):
                logger.error(f"Agent {aid} already exists.")
                return jsonify({"message": f'Agent "{aid}" already exists.'}), 401

            
            # Get the agent's user's public signing key:
            crt_u = sc.bytesToX509Certificate(user["crt_u"])
            pk_u = crt_u.public_key()

            # Get device and network information.
            device = application.get("device")
            ip = application.get("IP")
            port = application.get("port")
            a2a_card = application.get("a2a_card", None)

            # Ensure that IP+port is unique:
            existing = self.agents_collection.find_one({
                "IP": ip,
                "port": port
            })
    
            if existing is not None:
                logger.error(f"Address {ip}:{port} is already registered by agent {existing['aid']}")
                return jsonify({"message": f"Address {ip}:{port} is already registered by agent {existing['aid']}"})

            # Build the device and network information block.
            # The block includes:
            # - the aid, 
            # - device name, 
            # - IP address and port 
            dev_network_info = {
                "aid": aid, 
                "device": device, 
                "IP": ip, 
                "port": port,
                "a2a_card": a2a_card
            }
            
            # Get the agent certificate:
            agent_cert_bytes = base64.b64decode(application.get("agent_cert"))
            agent_cert = sc.bytesToX509Certificate(agent_cert_bytes)

            # Verify the agent's certificate:
            try:
                self.CA.verify(agent_cert)
            except:
                logger.error(f"Invalid agent certificate.")
                return jsonify({"message": "Invalid agent certificate"}), 401
            # Extract the aagent's public signing key 
            pk_a_bytes = agent_cert.public_key().public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw
            ) 
            
            # Get the agent's long term access control key:
            pac = application.get("pac")
            pac_bytes = base64.b64decode(application.get("pac"))
                
            # Build the agent cryptographic information block:
            crypto_info = {
                "pk_a": pk_a_bytes,
                "pac": pac_bytes,
                "pk_prov": self.PK_Prov.public_bytes(
                    encoding=sc.serialization.Encoding.Raw,
                    format=sc.serialization.PublicFormat.Raw
                )
            }

            # Verify the agent's signature using the user's public signing key:
            block = {}
            block.update(dev_network_info)
            block.update(crypto_info)
            agent_sig_bytes = base64.b64decode(application.get("agent_sig"))
            try:
                pk_u.verify(
                    agent_sig_bytes,
                    str(block).encode("utf-8")
                )
            except:
                logger.error(f"Invalid agent signature.")
                return jsonify({"message": "Invalid agent signature"}), 401
            
            # Extract the one-time keys.
            otks = application.get("otks")
            otks_bytes = [base64.b64decode(otk) for otk in otks]
            # Extract their signatures:
            otk_sigs = application.get("otk_sigs")
            otk_sigs_bytes = [base64.b64decode(sig) for sig in otk_sigs]
            # Verify the signatures of the one-time keys using the user's public signing key:
            for i, otk in enumerate(otks_bytes):
                try:
                    pk_u.verify(
                        otk_sigs_bytes[i],
                        otk
                    )
                except:
                    logger.error(f"Invalid one-time key signature.")
                    return jsonify({"message": "Invalid one-time key signature"}), 401
            
            # Check if any of the keys are being reused:
            if self.agents_collection.find_one({"agent_cert": agent_cert_bytes}):
                logger.error(f"Agent certificate already in use.")
                return jsonify({"message": "Agent certificate already in use"}), 401
            if self.agents_collection.find_one({"pac": pac_bytes}):
                logger.error(f"Access control key already in use.")
                return jsonify({"message": "Access control key already in use"}), 401
            for otk in otks_bytes:
                if self.agents_collection.find_one({"one_time_keys": {"$elemMatch": {"$eq": otk}}}):
                    logger.error(f"One-time key already in use.")
                    return jsonify({"message": "One-time key already in use"}), 401

            # Check the agent's contact rulebook:
            contact_rulebook = application.get("contact_rulebook", [])
            # Check if the rulebook is in the correct format.
            if not check_rulebook(contact_rulebook):
                return jsonify({"message": "Invalid contact rulebook format"}), 400

            # ========================================================================
            # At this stage, all required checks have been completed. The provider 
            # can now store the agent's cryptographic material in the database. 
            # ========================================================================

            # Define the agent "card":
            card = {
                "aid": aid,
                "device": device,
                "IP": ip,
                "port": port,
                "agent_cert": agent_cert_bytes,
                "pac": pac_bytes,
                "agent_sig": agent_sig_bytes
            }

            # Sign the agent card using the provider's private key:
            card_bytes = str(card).encode("utf-8")
            stamp = self.SK_Prov.sign(card_bytes) # universal stamp 
            # Convert signagure to bytes:
            stamp_bytes = base64.b64encode(stamp).decode("utf-8")

            self.agents_collection.insert_one({
                "aid": aid,
                "device": device,
                "IP": ip,
                "port": port,
                "agent_cert": agent_cert_bytes,
                "pac": pac_bytes,
                "one_time_keys": otks_bytes,
                # Contact rulebook:
                "contact_rulebook": contact_rulebook,
                # Signatures:
                "agent_sig": agent_sig_bytes,
                "one_time_key_sigs": otk_sigs_bytes,
                # Budget Counter:
                "counter": [],
                # A2A card:
                "a2a_card": a2a_card,
            })
            # Pop the JWT from the user's record so that it cannot be reused for other purposes.
            self.users_collection.update_one({"uid": uid}, {"$pull": {"auth_tokens": {"token": user_jwt}}})
            logger.log("PROVIDER", f"Agent {aid} registered successfully.")
            self.monitor.stop("provider:agent_register")
            logger.log("OVERHEAD", f"provider:agent_register: {self.monitor.elapsed('provider:agent_register')}")
            return jsonify({"message": "Agent registered successfully", "stamp": stamp_bytes}), 201

        @self.app.route('/access', methods=['POST'])
        def access():
            """
            This endpoint is used by the initiating agent to request a one-time key
            from the provider in order to receive an access control token from the
            receiving agent.

            The request should include the target agent ID (t_aid) in the request body.

            The response will include the one-time key and the user's identity key
            along with all other relevant cryptographic material of the receiving agent.
            """
            # Start stopwatch
            self.monitor.start("provider:access")
            # Convert PEM format string to bytes            
            i_aid_cert_bytes = request.environ.get('SSL_CLIENT_CERT').encode('utf-8')  # Extracts iniating agents's certificate
        

            data = request.json
            i_aid = data.get("i_aid", None) # the initiating agent
            t_aid = data.get("t_aid", None) # the receiving agent
            if not check_aid(t_aid):
                logger.error(f"Invalid agent ID format.")
                return jsonify({"message":f"Invalid agent ID: {t_aid} format."}), 400
            if not check_aid(i_aid):
                logger.error(f"Invalid agent ID format.")
                return jsonify({"message":f"Invalid agent ID: {i_aid} format."}), 400
            uid = t_aid.split(":")[0]

            # Make sure that the initiating agent is indeed who they claim to be:
            i_agent_metadata = self.agents_collection.find_one({"aid" : i_aid, "agent_cert": i_aid_cert_bytes})
            if i_agent_metadata is None:
                logger.error(f"ACCESS DENIED. IMPERSONATION.")
                return jsonify({"message":"Agent not found."}), 403

            user_metadata = self.users_collection.find_one({"uid" : uid})
            if user_metadata is None:
                logger.error(f"Cannot find agent owner with uid: {uid}.")
                return jsonify({"message":"Cannot find agent owner."}), 404

            # CONTACT POLCY ENFORCEMENT:
            # Get the agent's contact rulebook:
            agent_metadata_before = self.agents_collection.find_one({"aid" : t_aid})
            # Check if the agent is allowed to be contacted by the requesting agent.
            if agent_metadata_before is None:
                logger.error(f"Agent {t_aid} not found.")
                return jsonify({"message":"Agent not found."}), 404
            # Check if the initiating agent is allowed to be contacted by the requesting agent.
            contact_rulebook = agent_metadata_before.get("contact_rulebook", [])
            
            budget = match(contact_rulebook, i_aid)
            if budget < 0:
                logger.error(f"Agent {t_aid} has blocklisted Agent {i_aid}.")
                return jsonify({"message":"Access denied."}), 403

            if budget == 0:
                logger.error(f"Agent {t_aid} has not added Agent {i_aid} to its contact policy.")
                return jsonify({"message":"Access denied."}), 403

        
            # If the budget is greater than 0, the agent is allowed to be contacted.
            # 1) Ensure the target agent has one time keys available.
            # 2) Decrease the budget of the initiating agent by 1 (lowest possible is 0).
            # 3) Pop the last one-time key and its signature from the target agent entry.
            t_agent_metadata = self.agents_collection.find_one_and_update(
                {
                    "aid": t_aid,
                    "one_time_keys": { "$ne": [] },
                    "counter": {
                        "$not": {
                            "$elemMatch": {
                                "aid": i_aid,
                                "budget": { "$lte": 0 }
                            }
                        }
                    }
                },
                [
                    {
                        "$set": {
                            "counter": {
                                "$let": {
                                    "vars": {
                                        "hasEntry": {
                                            "$gt": [
                                                {
                                                    "$size": {
                                                        "$filter": {
                                                            "input": "$counter",
                                                            "cond": { "$eq": [ "$$this.aid", i_aid ] }
                                                        }
                                                    }
                                                },
                                                0
                                            ]
                                        }
                                    },
                                    "in": {
                                        "$cond": {
                                            "if": "$$hasEntry",
                                            "then": {
                                                "$map": {
                                                    "input": "$counter",
                                                    "as": "entry",
                                                    "in": {
                                                        "$cond": {
                                                            "if": { "$eq": [ "$$entry.aid", i_aid ] },
                                                            "then": {
                                                                "aid": "$$entry.aid",
                                                                "budget": {
                                                                    "$max": [ 0, { "$subtract": [ "$$entry.budget", 1 ] } ]
                                                                }
                                                            },
                                                            "else": "$$entry"
                                                        }
                                                    }
                                                }
                                            },
                                            "else": {
                                                "$concatArrays": [
                                                    "$counter",
                                                    # Initialization with budget - 1 because it consumes 
                                                    # a key from the budget immediately upon creation.
                                                    [ { "aid": i_aid, "budget": budget-1 } ]
                                                ]
                                            }
                                        }
                                    }
                                }
                            },
                            "one_time_keys": {
                                "$cond": {
                                    "if": { "$gt": [ { "$size": { "$ifNull": ["$one_time_keys", []] } }, 1 ] },
                                    "then": {
                                        "$slice": [
                                            "$one_time_keys",
                                            0,
                                            { "$subtract": [ { "$size": "$one_time_keys" }, 1 ] }
                                        ]
                                    },
                                    "else": []
                                }
                            },
                            "one_time_key_sigs": {
                                "$cond": {
                                    "if": { "$gt": [ { "$size": { "$ifNull": ["$one_time_key_sigs", []] } }, 1 ] },
                                    "then": {
                                        "$slice": [
                                            "$one_time_key_sigs",
                                            0,
                                            { "$subtract": [ { "$size": "$one_time_key_sigs" }, 1 ] }
                                        ]
                                    },
                                    "else": []
                                }
                            }
                        }
                    }
                ],
                return_document=False
            )
    

            # If agent not found or no keys left, return 404
            if t_agent_metadata is None:
                logger.error(f"Agent {t_aid} not found or no keys left.")
                return jsonify({"message": "Agent not found or no keys left."}), 404

            # Include the user's identity key in the response
            crt_u_bytes = user_metadata.get("crt_u")
            t_agent_metadata.update({"crt_u": crt_u_bytes})
            # Remove the one time keys from the response except the last one:
            t_agent_metadata['one_time_keys'] = [t_agent_metadata['one_time_keys'][-1]]
            t_agent_metadata['one_time_key_sigs'] = [t_agent_metadata['one_time_key_sigs'][-1]]
            # Remove the contact rulebook from the response
            t_agent_metadata.pop("contact_rulebook", None)
            t_agent_metadata.pop("_id", None)
            t_agent_metadata.pop("counter", None)

            # Stop stopwatch:
            self.monitor.stop("provider:access")
            logger.log("OVERHEAD", f"provider:access: {self.monitor.elapsed('provider:access')}")
            return jsonify(t_agent_metadata), 200
    
    def run(self):
        """Runs the web server."""
         # Set up SSL context with mTLS
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.ssl_context[0], keyfile=self.ssl_context[1])  # Server's cert and key
        context.load_verify_locations(cafile=saga.config.CA_WORKDIR+"/ca.crt")  # CA that issued client certs
        context.verify_mode = ssl.CERT_REQUIRED  # Force either client (user or agent) to present a valid cert
        self.app.run(host=self.host, port=self.port, ssl_context=context)


# Run the provider
if __name__ == "__main__":
    # Read the provider URI from config.py
    provider_uri = saga.config.PROVIDER_CONFIG.get('endpoint')
    # Read the port from this
    port = int(provider_uri.split(":")[-1])

    provider = Provider(
        workdir="./",
        name="provider",
        host="0.0.0.0",
        port=port,
        mongo_uri="mongodb://localhost:27017/saga",
        jwt_secret="supersecretkey"
    )
    provider.run()
