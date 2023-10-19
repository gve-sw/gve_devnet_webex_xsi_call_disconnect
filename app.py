"""
Copyright (c) 2023 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

from flask import Flask, request, render_template, redirect, session, url_for
from funcs import *
from requests_oauthlib import OAuth2Session
from rich.console import Console
from rich.table import Table
import os
import json
from flask import jsonify
from rich.panel import Panel


# Set environment variable for insecure transport; only for local testing without HTTPS (like ngrok)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Instantiate a console object for rich (nice logging in terminal)
console = Console()
EnvironmentManager.validate_env_variables()  # Validate environment variables at startup

app = Flask(__name__)
app.secret_key = EnvironmentManager.APP_SECRET_KEY

# shush Flask logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)


@app.route('/')
def root():
    """Root endpoint that redirects users to login."""
    return redirect(url_for('login'))


@app.route("/success")
def success():
    """Display call statistics after successful login."""
    return render_template('success.html', calls={"answered": answered_calls_count, "released": released_calls_count})


@app.route('/get_updated_calls', methods=['GET'])
def get_updated_calls():
    """Endpoint to fetch updated call statistics."""
    return jsonify({'answered': get_answered_calls_count(), 'released': get_released_calls_count()})


@app.route("/login")
def login():
    """Start the OAuth2 login flow and redirect user to OAuth provider."""
    # Create OAuth2 session
    teams = OAuth2Session(os.getenv('CLIENT_ID'), scope=EnvironmentManager.SCOPE, redirect_uri=EnvironmentManager.REDIRECT_URI)
    authorization_url, state = teams.authorization_url(EnvironmentManager.AUTHORIZATION_BASE_URL)
    session['oauth_state'] = state

    # Display session details using rich's Table
    table = Table()
    table.add_column("Key", justify="left", style="cyan", width=30)
    table.add_column("Value", style="magenta", width=50)
    table.add_row("CLIENT_ID", os.getenv('CLIENT_ID'))
    table.add_row("State", session['oauth_state'])
    table.add_row("PUBLIC_URL", EnvironmentManager.AUTHORIZATION_BASE_URL)
    table.add_row("Redirect URI", EnvironmentManager.REDIRECT_URI)
    table.add_row("Stored State", state)
    table.add_row("Authorization URL", authorization_url)

    console.print(Panel.fit(table, title="OAuth2 Session Details"))

    return redirect(authorization_url)


@app.route('/callback')
def callback():
    """Handle the OAuth2 callback, fetch the access token, and initiate call monitor."""
    console.print(Panel.fit("[dark_red]Handling Oauth2 callback, fetching access token, and initiating call monitoring...[/dark_red]"))
    try:
        # Display callback details
        table = Table()
        table.add_column("Key", justify="left", style="cyan", width=30)
        table.add_column("Value", style="magenta", width=50)
        table.add_row("Redirect URI", EnvironmentManager.REDIRECT_URI)
        table.add_row("CLIENT_ID", os.getenv('CLIENT_ID'))
        table.add_row("State", session['oauth_state'])

        console.print(Panel.fit(table, title="OAuth2 Callback Details"))
        auth_code = OAuth2Session(os.getenv('CLIENT_ID'), state=session['oauth_state'], redirect_uri=EnvironmentManager.REDIRECT_URI)
        token = auth_code.fetch_token(token_url=EnvironmentManager.TOKEN_URL, client_secret=os.getenv('CLIENT_SECRET'), authorization_response=request.url)

        if token:
            table = Table()
            table.add_column("Key", width=30)
            table.add_column("Value", width=50)
            for key, value in token.items():
                table.add_row(key, str(value))
            console.print(Panel.fit(table, title="Token Details"))

            session['oauth_token'] = token
            # Save token for future use
            with open('tokens.json', 'w') as json_file:
                json.dump(token, json_file)

            # Setup call monitor events
            call_monitor = CallMonitor(token['access_token'])
            call_monitor.setup_xsi_events()
            return redirect('/success')
        else:
            return {"error": "Failed to fetch access token"}, 400
    except Exception as e:
        console.print_exception()
        return {"error": "Failed to fetch access token"}, 400


def run():
    app.run(host='0.0.0.0', port=9001, debug=False)


if __name__ == '__main__':
    logger_manager.console.print(Panel.fit("[bold deep_sky_blue3]Please login to your Webex account... (PUBLIC_URL)[/bold deep_sky_blue3]"))
    run()
