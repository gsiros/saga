from pymongo import MongoClient
from datetime import datetime
from typing import List

from agent_backend.tools.base import BaseTool


# Internal fields used to scope a single shared collection per user/mailbox.
# Stripped from results before they leave the tool.
_OWNER_FIELD = "_owner"
_BOX_FIELD = "_box"
_INTERNAL_FIELDS = (_OWNER_FIELD, _BOX_FIELD, "_id")


class LocalEmailClientTool(BaseTool):
    def __init__(self, user_name: str, user_email: str):
        super().__init__("email")
        self.client = MongoClient(self.mongo_uri)
        self.user_email = user_email
        self.user_name = user_name

    def _collection(self):
        return self._get_collection(self.client)

    def _strip_internal(self, doc: dict) -> dict:
        for field in _INTERNAL_FIELDS:
            doc.pop(field, None)
        return doc

    def seed_data(self, data: List[dict]):
        collection = self._collection()

        for email in data:
            # If email is from self, add to self's sent box
            if email["from"] == f"{self.user_name} <{self.user_email}>":
                doc = {**email, _OWNER_FIELD: self.user_email, _BOX_FIELD: "sent"}
                collection.insert_one(doc)
                continue

            recepients = email["to"]
            for recipient in recepients:
                # format is "name <email>" - we want email out of it
                recipient_email = self._get_email_from_field(recipient)
                doc = {**email, _OWNER_FIELD: recipient_email, _BOX_FIELD: "inbox"}
                collection.insert_one(doc)

    def get_emails(self, where: str, limit: int = 10):
        """
        This method retrieves emails from the database.
        Returns a list of dictionaries containing the email details.
        """
        if where not in ["inbox", "sent"]:
            raise ValueError(f"Invalid search location: {where}. Must be 'inbox' or 'sent'.")

        collection = self._collection()
        emails = collection.find({
            _OWNER_FIELD: self.user_email,
            _BOX_FIELD: where,
        }).sort("time:", -1)
        if limit is not None:
            emails = emails.limit(limit)

        emails = [self._strip_internal(e) for e in emails]
        return emails

    def search_by_query(self, query: str, where: str):
        """
        This method searches for emails that match the query across any field.
        Returns a list of dictionaries containing the email details, sorted by time.
        """
        if where not in ["inbox", "sent"]:
            raise ValueError(f"Invalid search location: {where}. Must be 'inbox' or 'sent'.")

        collection = self._collection()
        # TODO: MIGHT BE SOMETHING WRONG WITH SEARCH FUNCTIONALITY HERE. LOOK INTO IT AT SOME POINT

        emails = collection.find({
            _OWNER_FIELD: self.user_email,
            _BOX_FIELD: where,
            "$or": [
                {"from": {"$regex": query, "$options": "i"}},
                {"subject": {"$regex": query, "$options": "i"}},
                {"body": {"$regex": query, "$options": "i"}},
                {"time:": {"$regex": query, "$options": "i"}}
            ]
        })

        emails = list(emails)
        emails.sort(key=lambda x: x["time:"], reverse=True)
        emails = [self._strip_internal(e) for e in emails]
        return emails

    def send_email(self, to: List[str], subject: str, body: str):
        """
        This method sends an email to the specified recipient(s).
        Returns True if the email was sent successfully, False otherwise.
        """
        collection = self._collection()
        time_sent = datetime.now()

        email = {
            "from": f"{self.user_name} <{self.user_email}>",
            "to": to,
            "subject": subject,
            "body": body,
            "time:": time_sent,
        }

        for receipient in to:
            recipient_email = self._get_email_from_field(receipient)
            doc = {**email, _OWNER_FIELD: recipient_email, _BOX_FIELD: "inbox"}
            collection.insert_one(doc)

        # Insert into self sent box
        sent_doc = {**email, _OWNER_FIELD: self.user_email, _BOX_FIELD: "sent"}
        collection.insert_one(sent_doc)

        return True
