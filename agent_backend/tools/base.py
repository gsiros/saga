from typing import List
from pymongo import MongoClient
from saga.config import MONGO_URI_FOR_TOOLS


SAGA_TOOLS_DB = "saga_tools"


class BaseTool:
    def __init__(self, tool_name):
        self.tool_name = tool_name
        self.db_name = SAGA_TOOLS_DB
        self.collection_name = tool_name
        self.mongo_uri = MONGO_URI_FOR_TOOLS

    def _get_collection(self, client: MongoClient):
        return client.get_database(self.db_name).get_collection(self.collection_name)

    def _clear_data(self):
        client = MongoClient(self.mongo_uri)
        collection = self._get_collection(client)
        collection.delete_many({})
        client.close()

    def _get_email_from_field(self, text: str) -> str:
        """
            Field will be in the format "name <email>", or just the email
            We want to extract the email address from this field
        """
        if not ("<" in text and ">" in text):
            return text.strip()

        return text.split("<")[1].split(">")[0]

    def _get_name_from_field(self, text: str) -> str:
        """
            Field will be in the format "name <email>"
            We want to extract the name from this field
        """
        return text.split("<")[0].strip()

    def seed_data(self, data: List[dict]):
        """
            Child class should implement a method to seed tool with specified data
        """
        raise NotImplementedError("Child class should implement a method to seed tool with specified data")
