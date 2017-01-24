#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Flask server to listen for Travis webhooks and post GitHub PR comments."""
import ConfigParser
import base64
import json
import logging

import requests
from OpenSSL.crypto import verify, load_publickey, FILETYPE_PEM, X509
from OpenSSL.crypto import Error as SignatureError

from flask import Flask, request

app = Flask(__name__)

config = ConfigParser.ConfigParser()
config.readfp(open(r'config.txt'))
TRAVIS_URL = config.get('Travis', 'TRAVIS_URL')
GH_TOKEN = config.get('GitHub', 'GH_TOKEN')
ORG = config.get('GitHub', 'ORG')
REPO = config.get('GitHub', 'REPO')

class GitHub(object):
    def __init__(self):
        self.token = GH_TOKEN
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        self.auth = (self.token, "x-oauth-basic")
        self.org = ORG
        self.repo = REPO
        self.base_url = "https://api.github.com/repos/%s/%s/" % (org, repo)

    def _headers(self, headers):
        if headers is None:
            headers = {}
        rv = self.headers.copy()
        rv.update(headers)
        return rv

    def post(self, url, data, headers=None):
        logger.debug("POST %s" % url)
        if data is not None:
            data = json.dumps(data)
        resp = requests.post(
            url,
            data=data,
            headers=self._headers(headers),
            auth=self.auth
        )
        resp.raise_for_status()
        return resp

    def patch(self, url, data, headers=None):
        logger.debug("PATCH %s" % url)
        if data is not None:
            data = json.dumps(data)
        resp = requests.patch(
            url,
            data=data,
            headers=self._headers(headers),
            auth=self.auth
        )
        resp.raise_for_status()
        return resp

    def get(self, url, headers=None):
        logger.debug("GET %s" % url)
        resp = requests.get(
            url,
            headers=self._headers(headers),
            auth=self.auth
        )
        resp.raise_for_status()
        return resp

    def post_comment(self, issue_number, product, body):
        user = self.get(urljoin(self.base_url, "/user")).json()
        issue_comments_url = urljoin(self.base_url, "issues/%s/comments" % issue_number)
        comments = self.get(issue_comments_url).json()
        title_line = format_comment_title(product)
        data = {"body": body}
        for comment in comments:
            if (comment["user"]["login"] == user["login"] and
                comment["body"].startswith(title_line)):
                comment_url = urljoin(self.base_url, "issues/comments/%s" % comment["id"])
                self.patch(comment_url, data)
                break
        else:
            self.post(issue_comments_url, data)


class GitHubCommentHandler(logging.Handler):
    def __init__(self, github, pull_number):
        logging.Handler.__init__(self)
        self.github = github
        self.pull_number = pull_number
        self.log_data = []

    def emit(self, record):
        try:
            msg = self.format(record)
            self.log_data.append(msg)
        except Exception:
            self.handleError(record)

    def send(self):
        self.github.post_comment(self.pull_number, "\n".join(self.log_data))
        self.log_data = []


def _check_authorized(signature, public_key, payload):
    """Reformat PEM-encoded public key for pyOpenSSL, then verify signature."""
    pkey_public_key = load_publickey(FILETYPE_PEM, public_key)
    certificate = X509()
    certificate.set_pubkey(pkey_public_key)
    verify(certificate, signature, payload, str('sha1'))


def _get_signature(req):
    """Extract raw bytes of the request signature from Travis."""
    signature = req.headers['SIGNATURE']
    return base64.b64decode(signature)


def _get_travis_public_key():
    """Return the PEM-encoded public key from Travis CI /config endpoint."""
    response = requests.get("%s/config" % TRAVIS_URL, timeout=10.0)
    response.raise_for_status()
    return response.json()['config']['notifications']['webhook']['public_key']


def _comment_to_github(payload):
    """Comment on the PR with extract from log."""
    pr = payload.get('pull_request_number')
    return 'Commented'


def setup_github_logging(args):
    gh_handler = None
    if args.comment_pr:
        github = GitHub()
        try:
            pr_number = int(args.comment_pr)
        except ValueError:
            pass
        else:
            gh_handler = GitHubCommentHandler(github, pr_number)
            gh_handler.setLevel(logging.INFO)
            logger.debug("Setting up GitHub logging")
            logger.addHandler(gh_handler)
    else:
        logger.warning("No PR number found; not posting to GitHub")
    return gh_handler


@app.route('/stability/travis', methods=['POST'])
def travis():
    """Respond to Travis webhook."""
    signature = _get_signature(request)
    payload = request.form['payload']
    try:
        public_key = _get_travis_public_key()
    except (requests.Timeout, requests.RequestException):
        return "Failed to retrieve Travis CI public key", 500

    try:
        _check_authorized(signature, public_key, payload)
    except SignatureError:
        return "Bad Travis CI Signature", 401

    json_payload = json.loads(payload)

    if json_payload.get('status_message') == 'Passed' and \
       json_payload.get('type') == 'pull_request':
        return comment_to_github(json_payload)
    return 'OK'

if __name__ == '__main__':
    app.run(debug=True)
