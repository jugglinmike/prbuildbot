#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Flask server to listen for Travis webhooks and post GitHub PR comments."""

import json
import logging

from webhook_handler import webhook_handler
from wptserve import server

logging.basicConfig(filename='wptserve.log', level=logging.DEBUG)


def handler(request, response):
    logging.debug(json.dumps(response.POST))
    logging.debug(json.dumps(response.headers))
    # payload =
    # signature =
    # response, code = webhook(handler(payload, signature))
    response.status(200, 'OK')


def hello(request, response):
    logging.debug(json.dumps(response.POST))
    logging.debug(json.dumps(response.headers))
    response.status(200, 'OK')


httpd = server.WebTestHttpd(port=8080, doc_root="./prbuildbot/",
                            routes=[
                                ("POST", "/travis/", handler),
                                ("GET", "/travis/", hello)
                            ])

if __name__ == '__main__':
    httpd.start(block=True)
