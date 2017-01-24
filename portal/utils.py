import os
import json
import datetime
from flask import request, flash, redirect, url_for
from threading import Lock

import globus_sdk

try:
    from urllib.parse import urlparse, urljoin
except:
    from urlparse import urlparse, urljoin

from portal import app


def load_portal_client():
    """Create an AuthClient for the portal"""
    return globus_sdk.ConfidentialAppAuthClient(
        app.config['PORTAL_CLIENT_ID'], app.config['PORTAL_CLIENT_SECRET'])


def is_safe_redirect_url(target):
    """https://security.openstack.org/guidelines/dg_avoid-unvalidated-redirects.html"""  # noqa
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))

    return redirect_url.scheme in ('http', 'https') and \
        host_url.netloc == redirect_url.netloc


def get_safe_redirect():
    """https://security.openstack.org/guidelines/dg_avoid-unvalidated-redirects.html"""  # noqa
    url = request.args.get('next')
    if url and is_safe_redirect_url(url):
        return url

    url = request.referrer
    if url and is_safe_redirect_url(url):
        return url

    return '/'


def get_portal_tokens(
        scopes=['openid', 'profile',
                'urn:globus:auth:scope:auth.globus.org:view_identities']):
    """
    Uses the client_credentials grant to get access tokens on the
    Portal's "client identity."
    """
    with get_portal_tokens.lock:
        if not get_portal_tokens.access_tokens:
            get_portal_tokens.access_tokens = {}

        scope_string = ' '.join(scopes)

        client = load_portal_client()
        tokens = client.oauth2_client_credentials_tokens(
            requested_scopes=scope_string)
        print tokens

        # walk all resource servers in the token response (includes the
        # top-level server, as found in tokens.resource_server), and store the
        # relevant Access Tokens
        for resource_server, token_info in tokens.by_resource_server.items():
            get_portal_tokens.access_tokens.update({
                resource_server: {
                    'token': token_info['access_token'],
                    'scope': token_info['scope'],
                    'expires_at': token_info['expires_at_seconds']
                }
            })
            print token_info["scope"]

        return get_portal_tokens.access_tokens


get_portal_tokens.lock = Lock()
get_portal_tokens.access_tokens = None


def store_tokens(tokens, username):
    outdir = os.path.join("./users/", username, "")
    if not os.path.exists(outdir):
        os.makedirs(outdir)
    data = tokens.by_resource_server
    data["timestamp"] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    with open(os.path.join(outdir, 'token.json'), 'w') as outfile:
        json.dump(data, outfile)


def store_idenities(identities, username):
    outdir = os.path.join("./users/", username, "")
    if not os.path.exists(outdir):
        os.makedirs(outdir)
    with open(os.path.join(outdir, 'identities.json'), "w") as outfile:
        json.dump(identities.data, outfile)


def get_all_ids(tokens, store_token=True, store_ids=True):
    # Adding this part to get an Auth client that knows about the
    # token and can access all off the user identities. Somewhat ugly
    # Globus might fix it
    auth_client = globus_sdk.AuthClient(
        authorizer=globus_sdk.AccessTokenAuthorizer(
            tokens.access_token))
    all_ids = auth_client.get('/p/whoami')
    username = None
    for iden in all_ids.data["identities"]:
        if iden["username"].endswith("@globusid.org"):
            username = iden["username"].replace("@globusid.org", "")
    if username is None:
        flash("Could not Globus ID username")
        return redirect(url_for('home'))
    if store_token:
        store_tokens(tokens, username)
    if store_ids:
        store_idenities(all_ids, username)
