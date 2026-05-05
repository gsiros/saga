from pymongo import MongoClient
from datetime import datetime, timedelta, time
from typing import List

from agent_backend.tools.base import BaseTool


_OWNER_FIELD = "_owner"
_INTERNAL_FIELDS = (_OWNER_FIELD, "_id")


class LocalCalendarTool(BaseTool):
    def __init__(self, user_name: str, user_email: str):
        super().__init__("calendar")
        self.client = MongoClient(self.mongo_uri)
        self.user_name = user_name
        self.user_email = user_email
        # TODO: Do not hard-code policy
        self.policy = {
            "start_time": "09:00:00",
            "end_time": "17:00:00",
            "start_day": "Monday",
            "end_day": "Friday"
        }

    def _collection(self):
        return self._get_collection(self.client)

    def _strip_internal(self, doc: dict) -> dict:
        for field in _INTERNAL_FIELDS:
            doc.pop(field, None)
        return doc

    def get_preference(self):
        return "Any time between {} and {} between {} and {} in the week".format(
            self.policy["start_time"],
            self.policy["end_time"],
            self.policy["start_day"],
            self.policy["end_day"]
        )

    def seed_data(self, data: List[dict]):
        collection = self._collection()

        for event in data:
            event["time_from"] = datetime.fromisoformat(event["time_from"])
            event["time_to"] = datetime.fromisoformat(event["time_to"])

            # Insert into self's calendar
            collection.insert_one({**event, _OWNER_FIELD: self.user_email})

            # format is "name <email>" - we want email out of it
            participants = event["participants"]
            for participant in participants:
                participant_email = self._get_email_from_field(participant)

                # Insert into recipient calendar, as long as the recipient is not self
                if participant_email != self.user_email:
                    collection.insert_one({**event, _OWNER_FIELD: participant_email})

    def get_upcoming_events(self, limit: int = 10):
        """
        This method retrieves a list of upcoming events from the user's calendar.
        Returns a list of dictionaries containing the event details.
        """
        collection = self._collection()

        # We want all calendar events that have not already ended
        now = datetime.now()
        events = collection.find({
            _OWNER_FIELD: self.user_email,
            "time_to": {"$gte": now},
        }).sort("time_from", 1)
        if limit is not None:
            events = events.limit(limit)

        events = [self._strip_internal(e) for e in events]
        return events

    def get_availability(self, time_from: str, time_to: str):
        """
        This method retrieves all events within the specified time-range, and then return the blocks of times where the user is free.
        """
        collection = self._collection()

        current = datetime.fromisoformat(time_from)
        end_time_dt = datetime.fromisoformat(time_to)

        # We want all calendar events that are within the specified time range
        events = collection.find({
            _OWNER_FIELD: self.user_email,
            "$or": [
                {"time_from": {"$gte": current, "$lte": end_time_dt}},
                {"time_to": {"$gte": current, "$lte": end_time_dt}},
                {"time_from": {"$lte": current}, "time_to": {"$gte": end_time_dt}}
            ]
        }).sort("time_from", 1)

        # Normalize start and end of policy hours for a given date
        def policy_bounds(dt):
            date_only = dt.date()
            start = datetime.combine(date_only, time.fromisoformat(self.policy["start_time"]))
            end = datetime.combine(date_only, time.fromisoformat(self.policy["end_time"]))
            return start, end

        # Helper to clip an interval [start_dt, end_dt) to policy hours, splitting across days if needed.
        def clip_to_policy(start_dt, end_dt):
            blocks = []
            current = start_dt
            # Process day-by-day.
            while current < end_dt:
                day_start, day_end = policy_bounds(current)
                # Advance current to next day's policy start if it's before policy hours.
                if current < day_start:
                    current = day_start
                # Determine the block end for the day.
                block_end = min(end_dt, day_end)
                if current < block_end:
                    blocks.append({"start": current.isoformat(), "end": block_end.isoformat()})
                # Move to next day.
                current = datetime.combine(current.date() + timedelta(days=1), time.fromisoformat(self.policy["start_time"]))
            return blocks

        # Start from the query's starting datetime.
        free_times = []

        # Iterate through all events in order.
        for event in events:
            event_start = event["time_from"]
            event_end = event["time_to"]

            # Skip events that end before our current pointer.
            if event_end <= current:
                continue

            # Adjust event_start if the event starts before 'current'.
            effective_event_start = max(event_start, current)

            # If there's a gap before this event starts, register it.
            if effective_event_start > current:
                free_gap_start = current
                free_gap_end = effective_event_start
                # Clip the free interval to policy hours.
                free_times.extend(clip_to_policy(free_gap_start, free_gap_end))

            # Move current pointer to the end of the event if it's later.
            current = max(current, event_end)
            if current >= end_time_dt:
                break

        # Any remaining time after the last event.
        if current < end_time_dt:
            free_times.extend(clip_to_policy(current, end_time_dt))

        return free_times


    def add_calendar_event(self,
                           time_from: str,
                           time_to: str,
                           event: str,
                           participants: List[str],
                           details: str):
        collection = self._collection()

        # Make sure time_from and time_to are ISO format
        try:
            # You can try to parse the string to a datetime object here if needed
            time_from = datetime.fromisoformat(time_from)
        except ValueError:
            print("Invalid date format for time_from")

        try:
            time_to = datetime.fromisoformat(time_to)
        except ValueError:
            print("Invalid date format for time_to")

        # Make sure user is in participants
        if f"{self.user_name} <{self.user_email}>" not in participants:
            participants.append(f"{self.user_name} <{self.user_email}>")

        participants = list(set(participants))  # Remove duplicates

        event = {
            "time_from": time_from,
            "time_to": time_to,
            "event": event,
            "participants": participants,
            "details": details,
        }

        # Now add it to the calendar of all participants
        for participant in participants:
            participant_email = self._get_email_from_field(participant)
            collection.insert_one({**event, _OWNER_FIELD: participant_email})

        return True
