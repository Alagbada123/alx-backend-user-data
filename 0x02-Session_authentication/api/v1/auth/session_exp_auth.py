#!/usr/bin/env python3
"""Session authentication with expiration module for the API.
"""
import os
from flask import request
from datetime import datetime, timedelta

from .session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """Session authentication class with expiration.
    """

    def __init__(self) -> None:
        """Initializes a new SessionExpAuth instance.
        """
        super().__init__()
        try:
            self.session_duration = int(os.getenv('SESSION_DURATION', '0'))
        except (ValueError, TypeError): # Catch specific errors for int conversion
            self.session_duration = 0

    def create_session(self, user_id=None):
        """Creates a session id for the user.
        """
        session_id = super().create_session(user_id)
        if session_id is None: # As per req: Return None if super() can’t create a Session ID
            return None
        
        session_dictionary = {
            'user_id': user_id,
            'created_at': datetime.now(),
        }
        self.user_id_by_session_id[session_id] = session_dictionary
        return session_id

    def user_id_for_session_id(self, session_id=None) -> str:
        """Retrieves the user id of the user associated with
        a given session id.
        """
        if session_id is None: # Req: Return None if session_id is None
            return None
        
        session_dictionary = self.user_id_by_session_id.get(session_id)
        if session_dictionary is None: # Req: Return None if user_id_by_session_id doesn’t contain key
            return None

        if self.session_duration <= 0: # Req: Return user_id if session_duration <= 0
            return session_dictionary.get('user_id')

        created_at = session_dictionary.get('created_at')
        if created_at is None: # Req: Return None if session_dictionary doesn’t contain created_at
            return None

        expiration_time = created_at + timedelta(seconds=self.session_duration)
        if expiration_time < datetime.now(): # Req: Return None if expired
            return None
            
        return session_dictionary.get('user_id') # Req: Otherwise, return user_id
