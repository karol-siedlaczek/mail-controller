import logging
from pathlib import Path
from flask import Flask, Response
from werkzeug.exceptions import MethodNotAllowed, NotFound
from mail_controller.conf.config import Config
from mail_controller.db.pool import Database
from mail_controller.api.routes import api as api_blueprint
from mail_controller.api.helpers import build_response, log_request
from mail_controller.exception.auth_exceptions import AuthException, AuthFailedException
from mail_controller.exception.api_exceptions import ApiError
from mail_controller.exception.validator_exceptions import ValidationError


def create_app(database: Database | None = None) -> Flask:
    app = Flask(__name__)
    config = Config.load()
    app.extensions["config"] = config
    app.extensions["db"] = database if database is not None else Database(
        host=config.pg_host, port=config.pg_port, dbname=config.pg_dbname,
        user=config.pg_user, password=config.pg_password,
    )
    app.json.sort_keys = False

    setup_paths(config)
    setup_logging(config)
    setup_error_handlers(app)
    app.register_blueprint(api_blueprint)
    return app


def setup_paths(config: Config) -> None:
    if config.logs_dir:
        try:
            Path(config.logs_dir).expanduser().mkdir(parents=True, exist_ok=True)
        except OSError:
            pass  # logs dir not writable (e.g. tests) — skip


def setup_logging(config: Config) -> None:
    level_name = (config.log_level or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    log_file = f"{config.logs_dir}/app.log"
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [pid=%(process)d] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root = logging.getLogger()
    root.setLevel(level)
    if not any(isinstance(h, logging.FileHandler)
               and getattr(h, "baseFilename", "") == log_file for h in root.handlers):
        try:
            f_handler = logging.FileHandler(log_file)
            f_handler.setFormatter(formatter)
            f_handler.setLevel(level)
            root.addHandler(f_handler)
        except OSError:
            pass  # logs dir not writable (e.g. tests) — stderr only
    logging.getLogger(__name__).info("Logging initialized (level=%s)", level_name)


def setup_error_handlers(app: Flask) -> None:
    @app.errorhandler(404)
    def handle_not_found(e: NotFound) -> Response:
        log_request(e, level="warning")
        return build_response(404, msg="Resource not found")

    @app.errorhandler(405)
    def handle_method_not_allowed(e: MethodNotAllowed) -> Response:
        log_request(e, level="warning")
        return build_response(405, msg=f"Method not allowed, valid methods are: {', '.join(e.valid_methods)}")

    @app.errorhandler(ValidationError)
    def handle_validation_error(e: ValidationError) -> Response:
        log_request(f"ValidationError: {e}", level="warning")
        return build_response(400, msg="Invalid request", detail=str(e))

    @app.errorhandler(AuthException)
    def handle_auth_exception(e: AuthException) -> Response:
        log_request(f"{type(e).__name__}: {e.msg}, details: {e.detail}", level="warning")
        return build_response(e.code, msg=e.msg, detail=None if isinstance(e, AuthFailedException) else e.detail)

    @app.errorhandler(ApiError)
    def handle_api_error(e: ApiError) -> Response:
        log_request(f"{type(e).__name__}: {e.msg}{f', details: {e.detail}' if e.detail else ''}", level=e.level)
        return build_response(e.code, msg=e.msg, detail=e.detail)

    @app.errorhandler(500)
    def handle_internal_server_error(e) -> Response:
        log_request(f"Unhandled exception: {e}", level="error")
        return build_response(500, msg="Internal server error")
