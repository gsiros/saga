"""
    Hello World example for two local SAGA agents to communicate *without* a LLM backend.
"""
import os

from saga.agent import Agent, get_agent_material
from saga.config import ROOT_DIR, UserConfig, get_index_of_agent

def main(mode, config_path, other_user_config_path=None, a2a_port=None):
    config = UserConfig.load(config_path, drop_extra_fields=True)

    # Find the index of the "email_agent" out of all config.agents
    agent_index = get_index_of_agent(config, "dummy_agent")
    if agent_index is None:
        raise ValueError("No agent with name 'dummy_agent' found in the configuration.")
    # Focus on first agent - infer credentials endpoint
    credentials_endpoint = os.path.join(ROOT_DIR, f"user/{config.email}:{config.agents[agent_index].name}/")
    # Read agent material
    material = get_agent_material(credentials_endpoint)
    agent = Agent(workdir=credentials_endpoint,
                  material=material,
                  local_agent=None, 
                  a2a_port=a2a_port)

    if mode == "listen":
        agent.listen()
    else:
        # Get endpoint for other agent
        other_user_config = UserConfig.load(other_user_config_path, drop_extra_fields=True)
        other_user_agent_index = get_index_of_agent(other_user_config, "dummy_agent")
        other_agent_credentials_endpoint = f"{other_user_config.email}:{other_user_config.agents[other_user_agent_index].name}"
        print(other_agent_credentials_endpoint)

        task = "Hello world!"
        agent.connect(other_agent_credentials_endpoint, task)


if __name__ == "__main__":
    # Get path to config file
    import sys
    mode = sys.argv[1]
    if mode not in ["listen", "query"]:
        raise ValueError("Mode (first argument) must be either 'listen' or 'query'")
    a2a_port = int(sys.argv[2])
    config_path = sys.argv[3]
    other_user_config_path = sys.argv[4] if len(sys.argv) > 4 else None
    
    if mode == "query" and other_user_config_path is None:
        raise ValueError("Endpoint (third argument) must be provided in query mode")
    main(mode=mode,
         config_path=config_path,
         other_user_config_path=other_user_config_path,
         a2a_port=a2a_port)
