"""
    Add some seed data into the running user's agent.
    Delete any existing data in storage before refreshing data
"""
import os
import json
from pymongo import MongoClient

from agent_backend.tools.base import SAGA_TOOLS_DB
from agent_backend.tools.calendar import LocalCalendarTool
from agent_backend.tools.email import LocalEmailClientTool
from agent_backend.tools.documents import LocalDocumentsTool
from saga.config import ROOT_DIR, MONGO_URI_FOR_TOOLS, UserConfig


def read_jsonl_data(path):
    data = []
    with open(path, 'r') as f:
        for line in f:
            data.append(json.loads(line))
    return data


def main(user_configs_path):
    # Start with clearing out all tool-related data under the saga_tools database
    mongo_client = MongoClient(MONGO_URI_FOR_TOOLS)
    mongo_client.drop_database(SAGA_TOOLS_DB)
    print(f"Dropped {SAGA_TOOLS_DB} database in tools mongo!")

    PATH_WITH_SEED_DATA = os.path.join(os.path.dirname(ROOT_DIR), "experiments", "data")
    for fpath in os.listdir(user_configs_path):
        config_path = os.path.join(user_configs_path, fpath)
        # Read user config
        config = UserConfig.load(config_path, drop_extra_fields=True)
        all_user_tools = []
        for agent in config.agents:
            all_user_tools.extend(agent.local_agent_config.tools)
        
        # Get user details
        name = config.name
        email = config.email
        
        # Read data for these tools and add to the agent
        for tool in all_user_tools:
            if tool == "email":
                tool_obj = LocalEmailClientTool(user_name=name, user_email=email)
            elif tool == "calendar":
                tool_obj = LocalCalendarTool(user_name=name, user_email=email)
            elif tool == "documents":
                tool_obj = LocalDocumentsTool(user_email=email)
            else:
                print(f"Tool {tool} not implemented yet. Skipping")
                continue

            # Read relevant data from data/, if there is any
            path = os.path.join(PATH_WITH_SEED_DATA, fpath.split(".yaml")[0], f"{tool}.jsonl")
            if os.path.exists(path):

                jsonl_data = read_jsonl_data(path)
                tool_obj.seed_data(jsonl_data)
                print("Seeded %s tool data for user %s" % (tool, name))

    print("Cleared all users' tool-related data and seeded with provided data!")


if __name__ == "__main__":
    main("../user_configs")
