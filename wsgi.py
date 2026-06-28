import os
from mail_controller.app import create_app
from mail_controller.validation.require import Require

bind_ip = os.getenv("GUNICORN_BIND_IP")
if bind_ip:
    Require.ip_address("GUNICORN_BIND_IP", bind_ip)

bind_port = os.getenv("GUNICORN_BIND_PORT")
if bind_port:
    Require.port("GUNICORN_BIND_PORT", int(bind_port))

app = create_app()
