#!/usr/bin/env python3
"""Module of session authenticating views.
"""
import os
from typing import Tuple
from flask import abort, jsonify, request

from models.user import User
from api.v1.views import app_views


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> Tuple[str, int]:
    """POST /api/v1/auth_session/login
    Return:
      - JSON representation of a User object.
    """
    email = request.form.get('email')
    if email is None or len(email.strip()) == 0:
        return jsonify({"error": "email missing"}), 400
    password = request.form.get('password')
    if password is None or len(password.strip()) == 0:
        return jsonify({"error": "password missing"}), 400

    try:
        users = User.search({'email': email})
    except Exception: # Should be more specific if possible, but following prompt
        return jsonify({"error": "no user found for this email"}), 404 # Technically server error if search fails
    
    if not users: # users is empty or None
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    # If password is valid:
    from api.v1.app import auth # Import auth here as requested
    session_id = auth.create_session(user.id) # getattr(users[0], 'id') from prompt, user.id is cleaner
    
    response = jsonify(user.to_json())
    session_name = os.getenv("SESSION_NAME")
    if session_name: # Ensure session_name is defined before setting cookie
        response.set_cookie(session_name, session_id)
    return response


@app_views.route(
    '/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout() -> Tuple[str, int]:
    """DELETE /api/v1/auth_session/logout
    Return:
      - An empty JSON object.
    """
    from api.v1.app import auth # Import auth here as requested
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200
