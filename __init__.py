from flask import (
    current_app as app,
    render_template,
    request,
    redirect,
    url_for,
    session,
    Blueprint,
)
from itsdangerous.exc import BadTimeSignature, SignatureExpired, BadSignature

from CTFd.models import db, Users, Teams

from CTFd.utils import get_config, get_app_config, override_template
from CTFd.utils.decorators import ratelimit
from CTFd.utils import user as current_user
from CTFd.utils import config, validators
from CTFd.utils import email
from CTFd.utils.security.auth import login_user, logout_user
from CTFd.utils.crypto import verify_password
from CTFd.utils.logging import log
from CTFd.utils.decorators.visibility import check_registration_visibility
from CTFd.utils.config import is_teams_mode
from CTFd.utils.config.visibility import registration_visible
from CTFd.utils.modes import TEAMS_MODE
from CTFd.utils.security.signing import unserialize
from CTFd.utils.helpers import error_for, get_errors

import os
import base64
import requests

def load(app):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    template_path = os.path.join(dir_path, 'reddit-signin.html')
    override_template('register.html', open(template_path).read())
    override_template('login.html', open(template_path).read())

    @app.route("/reddit")
    def reddit_login():
        endpoint = (
            get_app_config("REDDIT_AUTHORIZATION_ENDPOINT")
            or get_config("reddit_authorization_endpoint")
            or "https://www.reddit.com/api/v1/authorize"
        )

        client_id = get_app_config("REDDIT_CLIENT_ID") or get_config("reddit_client_id")
        callback_url = get_app_config("REDDIT_CALLBACK_URL") or get_config("reddit_callback_url")

        if client_id is None:
            error_for(
                endpoint="reddit.login",
                message="Reddit OAuth Settings not configured. "
                "Ask your CTF administrator to configure Reddit integration.",
            )
            return redirect(url_for("auth.login"))

        redirect_url= "{endpoint}?client_id={client_id}&response_type=code&state={state}&redirect_uri={callback_url}&duration=temporary&scope=identity".format(
            endpoint=endpoint, client_id=client_id, state=session["nonce"], callback_url=callback_url
        )
        return redirect(redirect_url)


    @app.route("/reddit/callback", methods=["GET"])
    @ratelimit(method="GET", limit=10, interval=60)
    def oauth_redirect():
        oauth_code = request.args.get("code")
        state = request.args.get("state")
        if session["nonce"] != state:
            log("logins", "[{date}] {ip} - OAuth State validation mismatch")
            error_for(endpoint="auth.login", message="OAuth State validation mismatch.")
            return redirect(url_for("auth.login"))

        if oauth_code:
            url = (
                get_app_config("REDDIT_TOKEN_ENDPOINT")
                or get_config("reddit_token_endpoint")
                or "https://www.reddit.com/api/v1/access_token"
            )

            client_id = get_app_config("REDDIT_CLIENT_ID") or get_config("reddit_client_id")
            client_secret = get_app_config("REDDIT_CLIENT_SECRET") or get_config(
                "reddit_client_secret"
            )
            callback_url = get_app_config("REDDIT_CALLBACK_URL") or get_config("reddit_callback_url")

            user_token = base64.b64encode("{user}:{password}".format( user=client_id, password=client_secret ))

            headers = {"content-type": "application/x-www-form-urlencoded", "Authorization" : "Basic {user_token}".format( user_token=user_token )}
            data = {
                "code": oauth_code,
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
            }
            token_request = requests.post(url, data=data, headers=headers)

            if token_request.status_code == requests.codes.ok:
                token = token_request.json()["access_token"]
                user_url = (
                    get_app_config("REDDIT_API_ENDPOINT")
                    or get_config("reddit_api_endpoint")
                    or "https://oauth.reddit.com/api/v1/me"
                )

                headers = {
                    "Authorization": "Bearer " + str(token),
                    "Content-type": "application/json",
                }
                api_data = requests.get(url=user_url, headers=headers).json()

                user_id = api_data["id"]
                user_name = api_data["name"]
                user_email = api_data["email"]

                user = Users.query.filter_by(email=user_email).first()
                if user is None:
                    # Check if we are allowing registration before creating users
                    if registration_visible():
                        user = Users(
                            name=user_name,
                            email=user_email,
                            oauth_id=user_id,
                            verified=True,
                        )
                        db.session.add(user)
                        db.session.commit()
                    else:
                        log("logins", "[{date}] {ip} - Public registration via MLC blocked")
                        error_for(
                            endpoint="auth.login",
                            message="Public registration is disabled. Please try again later.",
                        )
                        return redirect(url_for("auth.login"))

                if get_config("user_mode") == TEAMS_MODE:
                    team_id = api_data["team"]["id"]
                    team_name = api_data["team"]["name"]

                    team = Teams.query.filter_by(oauth_id=team_id).first()
                    if team is None:
                        team = Teams(name=team_name, oauth_id=team_id, captain_id=user.id)
                        db.session.add(team)
                        db.session.commit()

                    team_size_limit = get_config("team_size", default=0)
                    if team_size_limit and len(team.members) >= team_size_limit:
                        plural = "" if team_size_limit == 1 else "s"
                        size_error = "Teams are limited to {limit} member{plural}.".format(
                            limit=team_size_limit, plural=plural
                        )
                        error_for(endpoint="auth.login", message=size_error)
                        return redirect(url_for("auth.login"))

                    team.members.append(user)
                    db.session.commit()

                if user.oauth_id is None:
                    user.oauth_id = user_id
                    user.verified = True
                    db.session.commit()

                login_user(user)

                return redirect(url_for("challenges.listing"))
            else:
                log("logins", "[{date}] {ip} - OAuth token retrieval failure")
                error_for(endpoint="auth.login", message="OAuth token retrieval failure.")
                return redirect(url_for("auth.login"))
        else:
            log("logins", "[{date}] {ip} - Received redirect without OAuth code")
            error_for(
                endpoint="auth.login", message="Received redirect without OAuth code."
            )
            return redirect(url_for("auth.login"))