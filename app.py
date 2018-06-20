import cloudevents
from cloudevents import WebhookDestination
from flask import Flask, request, jsonify
from flask_cors import CORS
import socket
import re


# From: https://stackoverflow.com/questions/2532053/validate-a-hostname-string
# Added allowing port-number
def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)(:\d+)?$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


app = Flask(__name__)
#CORS(app)

SUPPORTED_PROTOCOLS = frozenset(["http", "https"])


def determine_origin():
    origin = request.headers.get("Origin")
    if origin is not None and origin != "":
        return origin

    host = request.headers.get("Host")
    if host is not None:
        return host

    return socket.gethostname()


def error_response(msg, **kwargs):
    status = 400
    if "status" in kwargs:
        status = kwargs.pop("status")
    return jsonify(dict(err=msg, **kwargs)), 400

construct_url = "{}://{}/{}".format

@app.route("/<protocol>/<domain>/", methods=["POST"])
@app.route("/<protocol>/<domain>/<path:path>", methods=["POST"])
def proxy(protocol, domain, path=""):
    json = request.get_json()
    if json is None:
        return error_response("Must post JSON body")

    ce_event = None
    try:
        ce_event = cloudevents.parse(json)
    except RuntimeError as ex:
        return error_response("Failed to parse Event", detail=str(ex))

    origin = determine_origin()

    protocol = protocol.lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        return error_response("Protocol must be http or https")

    if not is_valid_hostname(domain):
        return error_response("Must include a valid domain name")
    url = construct_url(protocol, domain, path)

    dest = WebhookDestination(origin, url)

    if not dest.may_send_webhook():
        return error_response("Destination not accepting CloudEvents",
                              dest=url, origin=origin)

    try:
        code, body = dest.send(ce_event)
        return body, code
    except RuntimeError as e:
        return error_response("Error sending cloud event", detail=str(e), status=500)
