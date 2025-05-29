#!/usr/bin/env python3
"""Session authentication with expiration
and storage support module for the API.
"""
from flask import request
from datetime import datetime, timedelta

from models.user_session import UserSession
from .session_exp_auth import SessionExpAuth


class SessionDBAuth(SessionExpAuth):
    """Session authentication class with expiration and storage support.
    """

    def create_session(self, user_id=None) -> str:
        """Creates and stores a session id for the user.
        """
        session_id = super().create_session(user_id)

        if session_id is None:  # Check if super call failed
            return None

        kwargs = {
            'user_id': user_id,
            'session_id': session_id,
        }
        user_session = UserSession(**kwargs)
        user_session.save()
        # UserSession.save_to_file() # if Base has this mechanism like User
        return session_id

    def user_id_for_session_id(self, session_id=None) -> str:
        """Retrieves the user id of the user associated with
        a given session id.
        """
        if session_id is None:
            return None
        try:
            user_sessions = UserSession.search({'session_id': session_id})
        except Exception:  # Broad exception, consider specific ones if known
            return None

        if not user_sessions:  # If no session found in DB
            return None

        user_session = user_sessions[0]  # Get the first matching session

        if self.session_duration <= 0:
            return user_session.user_id

        created_at = user_session.created_at
        if created_at is None:
            return None

        expiration_time = created_at + timedelta(seconds=self.session_duration)
        if expiration_time < datetime.now():
            # user_session.remove()
            return None

        return user_session.user_id

    def destroy_session(self, request=None) -> bool:
        """Destroys an authenticated session from the database.
        """
        if request is None:
            return False

        session_id = self.session_cookie(request)
        if session_id is None:
            return False
        # Remove from DB
        try:
            user_sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return False  # Error during search
        if not user_sessions:  # No session found in DB to destroy
            return False
        user_session_to_delete = user_sessions[0]
        user_session_to_delete.remove()

        return True
