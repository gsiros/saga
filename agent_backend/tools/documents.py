from pymongo import MongoClient
from typing import List
from datetime import datetime

from agent_backend.tools.base import BaseTool


_OWNER_FIELD = "_owner"
_INTERNAL_FIELDS = (_OWNER_FIELD, "_id")


class LocalDocumentsTool(BaseTool):
    def __init__(self, user_email: str):
        super().__init__("documents")
        self.client = MongoClient(self.mongo_uri)
        self.user_email = user_email

    def _collection(self):
        return self._get_collection(self.client)

    def _strip_internal(self, doc: dict) -> dict:
        for field in _INTERNAL_FIELDS:
            doc.pop(field, None)
        return doc

    def seed_data(self, data: List[dict]):
        collection = self._collection()

        for document in data:
            collection.insert_one({**document, _OWNER_FIELD: self.user_email})

    def search_by_query(self, query: str, limit: int = None) -> List[dict]:
        """
        Retrieve documents from the database based on the query.
        """
        collection = self._collection()

        owner_filter = {_OWNER_FIELD: self.user_email}
        if query == "":
            documents = collection.find(owner_filter)
        else:
            documents = collection.find({
                **owner_filter,
                "$or": [
                    {"time": {"$regex": query, "$options": "i"}},
                    {"filename": {"$regex": query, "$options": "i"}},
                    {"content": {"$regex": query, "$options": "i"}},
                ]
            })
        documents = documents.sort("time", -1)

        if limit is not None:
            documents = documents.limit(limit)

        documents = [self._strip_internal(d) for d in documents]
        return documents

    def create_document(self, filename: str, content: str) -> bool:
        """
            Write document to file
        """
        collection = self._collection()

        document = {
            "time": datetime.now(),
            "filename": filename,
            "content": content,
            _OWNER_FIELD: self.user_email,
        }
        collection.insert_one(document)
        return True
