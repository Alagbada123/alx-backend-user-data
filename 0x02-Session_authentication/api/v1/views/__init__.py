#!/usr/bin/env python3
""" DocDocDocDocDocDoc
"""
from flask import Blueprint

app_views = Blueprint("app_views", __name__, url_prefix="/api/v1")

from api.v1.views.index import *
from api.v1.views.users import *

from models.user import User  # Ensuring User is explicitly available b4 use
User.load_from_file()

from api.v1.views.session_auth import *  # Added as per Req 8
