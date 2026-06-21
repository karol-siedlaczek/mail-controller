#!/usr/bin/env python3
# Karol Siedlaczek 2026
import os
import json
import logging
from logging.handlers import RotatingFileHandler
from enum import Enum
from getpass import getpass
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Optional, Dict, NoReturn
import base64
import hmac
import hashlib
import binascii
import typer
import click
import requests
from rich.console import Console
from rich.table import Table, box

ENV_VAR_API_URL = "MAILADMIN_API_URL"
ENV_VAR_TOKEN = "MAILADMIN_TOKEN"
ENV_VAR_LOG_FILE = "MAILADMIN_LOG_FILE"
ENV_VAR_LOG_LEVEL = "MAILADMIN_LOG_LEVEL"
SETTINGS_FILE = Path("~/.mailctl").expanduser()
LOGGER = logging.getLogger("mailctl-cli")

app = typer.Typer(add_completion=True, help="CLI for managing mailboxes via Mail Admin")
domain_app = typer.Typer(help="Manage domains")
user_app = typer.Typer(help="Manage mailboxes")
forward_app = typer.Typer(help="Manage forwardings")
sendas_app = typer.Typer(help="Manage send-as (sender-login) grants")
token_app = typer.Typer(help="Token identity / scope / HMAC generation")
app.add_typer(domain_app, name="domain")
app.add_typer(user_app, name="user")
app.add_typer(forward_app, name="forward")
app.add_typer(sendas_app, name="sendas")
app.add_typer(token_app, name="token")
console = Console()


class ExitCode(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


class Format(Enum):
    TABLE = "table"
    JSON = "json"
    KEY_VALUE = "kv"
    VALUE = "value"

    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]

    @classmethod
    def default(cls) -> "Format":
        return Format.TABLE

    @classmethod
    def from_string(cls, val: str) -> "Format":
        try:
            return Format(val)
        except ValueError:
            raise typer.BadParameter(f"Unknown format: {val}, must be one of: {', '.join(Format.values())}")


class Opt:
    @staticmethod
    def timeout(default: int = 10) -> Any:
        return typer.Option(default, "--timeout", "-t", help="API request timeout in seconds")

    @staticmethod
    def format(default: str | None = None) -> Any:
        return typer.Option(default or Format.default().value, "--format", "-f",
                            help=f"Output format: {', '.join(Format.values())}")

    @staticmethod
    def columns() -> Any:
        return typer.Option(None, "-c", "--column",
                            help="Column(s) to include; repeat for multiple")

    @staticmethod
    def domain() -> Any:
        return typer.Option(None, "-d", "--domain", help="Filter by domain")


@dataclass
class Settings:
    api_url: str | None
    token: str | None
    log_file: str | None
    log_level: str | None
    format: Format | None


@dataclass
class CmdResult:
    data: Any
    exit_code: ExitCode

    @classmethod
    def from_response(cls, response: "requests.Response", exit_code: "ExitCode | None" = None) -> "CmdResult":
        data = cls._parse_response(response)
        exit_code = exit_code or (ExitCode.OK if response.ok else ExitCode.CRITICAL)
        return cls(data, exit_code)

    @classmethod
    def from_dict(cls, data: Any, exit_code: "ExitCode | None" = None) -> "CmdResult":
        return cls(data, exit_code or ExitCode.OK)

    @staticmethod
    def _parse_response(response) -> Any:
        try:
            payload = response.json()
        except ValueError:
            return {"message": response.text}
        if not isinstance(payload, dict):
            return payload
        payload.pop("timestamp", None)
        if response.ok:
            payload.pop("path", None)
            payload.pop("http_code", None)
            payload.pop("http_status", None)
            payload.pop("method", None)
            payload = payload.get("data", payload)
        return payload

    def _filter_data(self, columns):
        if not columns:
            return self.data
        if isinstance(self.data, list):
            return [{c: row.get(c) for c in columns} if isinstance(row, dict) else row
                    for row in self.data]
        if isinstance(self.data, dict):
            return {c: self.data.get(c) for c in columns}
        return self.data

    def render_and_exit(self, context_info: str | None = None, columns=None) -> NoReturn:
        settings = get_ctx_settings()
        fmt = settings.format
        data = self._filter_data(columns) if self.exit_code == ExitCode.OK else self.data

        def _print(value="") -> None:
            if self.exit_code == ExitCode.OK:
                console.print(value)
            else:
                console.print(value, style="red", highlight=False)

        if fmt == Format.JSON:
            _print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        elif fmt == Format.VALUE:
            rows = data if isinstance(data, list) else [data]
            for row in rows:
                if isinstance(row, dict):
                    for v in row.values():
                        _print(v)
                else:
                    _print(row)
        elif fmt == Format.KEY_VALUE:
            rows = data if isinstance(data, list) else [data]
            for i, row in enumerate(rows):
                if isinstance(row, dict):
                    width = max((len(str(k)) for k in row), default=0)
                    for k, v in row.items():
                        _print(f"{str(k):<{width}} = {v}")
                    if i != len(rows) - 1:
                        _print()
                else:
                    _print(row)
        else:  # TABLE
            rows = data if isinstance(data, list) else [data]
            rows = [r for r in rows if isinstance(r, dict)]
            if rows:
                table = Table(show_header=True, header_style="bold", expand=True,
                              show_lines=True, box=box.ROUNDED)
                cols = list(rows[0].keys())
                for c in cols:
                    table.add_column(str(c), overflow="fold")
                for row in rows:
                    table.add_row(*["-" if row.get(c) is None else str(row.get(c)) for c in cols])
                _print(table)
            elif data:
                _print(data)

        LOGGER.log(logging.INFO if self.exit_code == ExitCode.OK else logging.ERROR,
                   f"{f'Result for {context_info}: ' if context_info else ''}{data}")
        raise typer.Exit(code=self.exit_code.value)


@dataclass(frozen=True)
class Client:
    base_url: str
    session: requests.Session
    timeout: int

    @classmethod
    def init(cls, base_url: str, token: Optional[str] = None, *, timeout: int) -> "Client":
        base_url = base_url.rstrip("/")
        session = requests.Session()
        if token:
            session.headers.update({"Authorization": f"Bearer {token}"})
        session.headers.update({"Accept": "application/json"})
        try:
            session.request("GET", f"{base_url}/ping", timeout=10)
        except requests.RequestException as e:
            CmdResult.from_dict({"msg": "Error connecting to API server", "error": str(e)},
                                ExitCode.CRITICAL).render_and_exit()
        return cls(base_url, session, timeout or 10)

    def request(self, method: str, path: str, *, params=None, json_body=None) -> "requests.Response":
        return self.session.request(method=method.upper(), url=f"{self.base_url}{path}",
                                    params=params, json=json_body, timeout=self.timeout)


# ── callback + helpers ────────────────────────────────────────────────────────
@app.callback()
def main(
    ctx: typer.Context,
    api_url: str = typer.Option(None, "-u", "--api-url", envvar=ENV_VAR_API_URL,
                                help=f"API base URL (env {ENV_VAR_API_URL} or API_URL in {SETTINGS_FILE})"),
    token: str = typer.Option(None, "-T", "--token", envvar=ENV_VAR_TOKEN,
                              help=f"Bearer token <id>.<token> (env {ENV_VAR_TOKEN} or TOKEN in {SETTINGS_FILE})"),
    log_file: str = typer.Option(None, "--log-file", envvar=ENV_VAR_LOG_FILE),
    log_level: str = typer.Option(None, "--log-level", envvar=ENV_VAR_LOG_LEVEL),
) -> None:
    ctx.obj = Settings(api_url=api_url, token=token, log_file=log_file, log_level=log_level, format=None)


def get_ctx_settings() -> Settings:
    s = click.get_current_context().obj
    if not isinstance(s, Settings):
        raise typer.Exit(code=2)
    return s


def setup_logging(log_file: str | None, log_level: str | None) -> None:
    if not log_file:
        LOGGER.disabled = True
        return
    logger = logging.getLogger()
    if any(getattr(h, "_mailctl_handler", False) for h in logger.handlers):
        return
    level = getattr(logging, (log_level or "INFO").upper(), None)
    if not isinstance(level, int):
        raise typer.BadParameter(f"Unknown log level: {log_level}")
    handler = RotatingFileHandler(log_file, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="UTF-8")
    handler._mailctl_handler = True
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s [pid=%(process)d] [%(name)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)
    logger.setLevel(level)


def load_settings(ctx: typer.Context, fmt: str | None = None) -> Settings:
    settings = ctx.obj
    if not isinstance(settings, Settings):
        raise typer.Exit(code=2)
    file_settings: dict[str, str] = {}
    if SETTINGS_FILE.exists():
        mode = SETTINGS_FILE.stat().st_mode & 0o777
        if mode != 0o600:
            raise typer.BadParameter(
                f"Invalid permissions for {SETTINGS_FILE}: expected 600, got {mode:o}; run: chmod 600 {SETTINGS_FILE}")
        for line in SETTINGS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            file_settings[k.strip().upper()] = v.strip()
    if not settings.api_url:
        settings.api_url = file_settings.get("API_URL")
    if not settings.token:
        settings.token = file_settings.get("TOKEN")
    if not settings.log_file:
        settings.log_file = file_settings.get("LOG_FILE")
    if not settings.log_level:
        settings.log_level = file_settings.get("LOG_LEVEL")
    setup_logging(settings.log_file, settings.log_level)
    settings.format = Format.from_string(fmt)
    if not settings.api_url:
        raise typer.BadParameter(
            f"Provide --api-url, set {ENV_VAR_API_URL}, or add API_URL=<value> in {SETTINGS_FILE}")
    return settings


def _client(ctx, fmt, timeout):
    s = load_settings(ctx, fmt)
    return Client.init(s.api_url, s.token, timeout=timeout)


# ── version / token ───────────────────────────────────────────────────────────
@app.command(help="Versions and author")
def version(ctx: typer.Context, timeout: int = Opt.timeout(),
            format: str = Opt.format(), columns: list[str] = Opt.columns()) -> None:
    r = _client(ctx, format, timeout).request("GET", "/api/version")
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@token_app.command(help="Current identity (allowed CIDRs, permissions)")
def identity(ctx: typer.Context, timeout: int = Opt.timeout(),
             format: str = Opt.format(), columns: list[str] = Opt.columns()) -> None:
    r = _client(ctx, format, timeout).request("GET", "/api/token/identity")
    result = CmdResult.from_response(r)
    if isinstance(result.data, dict) and result.data.get("permissions"):
        result.data["permissions"] = [f"{p['scope']}:{p['action']}" for p in result.data["permissions"]]
    result.render_and_exit(ctx.info_name, columns)


@token_app.command(help="Permissions for the current identity")
def scope(ctx: typer.Context, timeout: int = Opt.timeout(),
          format: str = Opt.format(), columns: list[str] = Opt.columns()) -> None:
    r = _client(ctx, format, timeout).request("GET", "/api/token/scope")
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@token_app.command(name="gen-hmac", help="Generate TOKEN_<ID>_HMAC for server configuration")
def gen_hmac(
    hmac_key_b64: str = typer.Option(None, "--hmac-key-b64", help="Base64 HMAC key (≥32 bytes); prompted if omitted"),
    token_id: str = typer.Option(None, "--id", "-i", help="Identity id; prompted if omitted"),
    token_value: str = typer.Option(None, "--token", "-T", help="Raw token; prompted if omitted"),
) -> None:
    if token_id is None:
        token_id = input("Token ID: ").strip()
    if hmac_key_b64 is None:
        hmac_key_b64 = getpass("HMAC key (base64): ").strip()
    if token_value is None:
        t1, t2 = getpass("Token value: ").strip(), getpass("Confirm token value: ").strip()
        if t1 != t2 or not t1:
            raise typer.BadParameter("Token values empty or do not match")
        token_value = t1
    try:
        key = base64.b64decode(hmac_key_b64, validate=True)
    except binascii.Error:
        raise typer.BadParameter("Invalid HMAC key: not valid base64 (openssl rand -base64 32)")
    if len(key) < 32:
        raise typer.BadParameter("HMAC key must decode to at least 32 bytes (openssl rand -base64 32)")
    digest = hmac.new(key, token_value.encode(), hashlib.sha256).hexdigest()
    typer.secho("\nSuccess!\n", fg=typer.colors.GREEN)
    print("Add the following environment variable to the server:")
    print(f"TOKEN_{token_id.upper()}_HMAC={digest}\n")


# ── domain ────────────────────────────────────────────────────────────────────
@domain_app.command("list", help="List domains")
def domain_list(ctx: typer.Context, timeout: int = Opt.timeout(),
                format: str = Opt.format(), columns: list[str] = Opt.columns()) -> None:
    r = _client(ctx, format, timeout).request("GET", "/api/domains")
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@domain_app.command("add", help="Add a domain")
def domain_add(ctx: typer.Context, domain: str = typer.Argument(...),
               dkim_selector: str = typer.Option(None, "--dkim-selector"),
               active: bool = typer.Option(True, "--active/--inactive"),
               timeout: int = Opt.timeout(), format: str = Opt.format(),
               columns: list[str] = Opt.columns()) -> None:
    body = {"domain": domain, "active": active}
    if dkim_selector:
        body["dkim_selector"] = dkim_selector
    r = _client(ctx, format, timeout).request("POST", "/api/domains", json_body=body)
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@domain_app.command("show", help="Show a domain")
def domain_show(ctx: typer.Context, domain: str = typer.Argument(...),
                timeout: int = Opt.timeout(), format: str = Opt.format(),
                columns: list[str] = Opt.columns()) -> None:
    r = _client(ctx, format, timeout).request("GET", f"/api/domains/{domain}")
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@domain_app.command("set", help="Update a domain (dkim selector / active)")
def domain_set(ctx: typer.Context, domain: str = typer.Argument(...),
               dkim_selector: str = typer.Option(None, "--dkim-selector"),
               active: Optional[bool] = typer.Option(None, "--active/--inactive"),
               timeout: int = Opt.timeout(), format: str = Opt.format(),
               columns: list[str] = Opt.columns()) -> None:
    body: dict[str, Any] = {}
    if dkim_selector is not None:
        body["dkim_selector"] = dkim_selector
    if active is not None:
        body["active"] = active
    r = _client(ctx, format, timeout).request("PATCH", f"/api/domains/{domain}", json_body=body)
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@domain_app.command("rm", help="Delete a domain")
def domain_rm(ctx: typer.Context, domain: str = typer.Argument(...),
              timeout: int = Opt.timeout(), format: str = Opt.format(),
              columns: list[str] = Opt.columns()) -> None:
    r = _client(ctx, format, timeout).request("DELETE", f"/api/domains/{domain}")
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


# ── user ──────────────────────────────────────────────────────────────────────
@user_app.command("list", help="List mailboxes")
def user_list(ctx: typer.Context, domain: str = Opt.domain(), timeout: int = Opt.timeout(),
              format: str = Opt.format(), columns: list[str] = Opt.columns()) -> None:
    params = {"domain": domain} if domain else None
    r = _client(ctx, format, timeout).request("GET", "/api/users", params=params)
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@user_app.command("add", help="Create a mailbox")
def user_add(ctx: typer.Context, email: str = typer.Argument(...),
             password: str = typer.Option(None, "--password", help="Prompted if omitted"),
             quota_bytes: int = typer.Option(0, "--quota-bytes"),
             active: bool = typer.Option(True, "--active/--inactive"),
             timeout: int = Opt.timeout(), format: str = Opt.format(),
             columns: list[str] = Opt.columns()) -> None:
    if not password:
        p1, p2 = getpass("Password: "), getpass("Confirm password: ")
        if p1 != p2 or not p1:
            raise typer.BadParameter("Passwords empty or do not match")
        password = p1
    body = {"email": email, "password": password, "quota_bytes": quota_bytes, "active": active}
    r = _client(ctx, format, timeout).request("POST", "/api/users", json_body=body)
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@user_app.command("show", help="Show a mailbox")
def user_show(ctx: typer.Context, email: str = typer.Argument(...),
              timeout: int = Opt.timeout(), format: str = Opt.format(),
              columns: list[str] = Opt.columns()) -> None:
    r = _client(ctx, format, timeout).request("GET", f"/api/users/{email}")
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@user_app.command("passwd", help="Set/reset a mailbox password")
def user_passwd(ctx: typer.Context, email: str = typer.Argument(...),
                password: str = typer.Option(None, "--password", help="Prompted if omitted"),
                timeout: int = Opt.timeout(), format: str = Opt.format(),
                columns: list[str] = Opt.columns()) -> None:
    if not password:
        p1, p2 = getpass("Password: "), getpass("Confirm password: ")
        if p1 != p2 or not p1:
            raise typer.BadParameter("Passwords empty or do not match")
        password = p1
    r = _client(ctx, format, timeout).request("POST", f"/api/users/{email}/password",
                                               json_body={"password": password})
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@user_app.command("set", help="Update a mailbox (quota / active)")
def user_set(ctx: typer.Context, email: str = typer.Argument(...),
             quota_bytes: Optional[int] = typer.Option(None, "--quota-bytes"),
             active: Optional[bool] = typer.Option(None, "--active/--inactive"),
             timeout: int = Opt.timeout(), format: str = Opt.format(),
             columns: list[str] = Opt.columns()) -> None:
    body: dict[str, Any] = {}
    if quota_bytes is not None:
        body["quota_bytes"] = quota_bytes
    if active is not None:
        body["active"] = active
    r = _client(ctx, format, timeout).request("PATCH", f"/api/users/{email}", json_body=body)
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@user_app.command("rm", help="Delete a mailbox")
def user_rm(ctx: typer.Context, email: str = typer.Argument(...),
            timeout: int = Opt.timeout(), format: str = Opt.format(),
            columns: list[str] = Opt.columns()) -> None:
    r = _client(ctx, format, timeout).request("DELETE", f"/api/users/{email}")
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


# ── forward ───────────────────────────────────────────────────────────────────
@forward_app.command("list", help="List forwardings")
def forward_list(ctx: typer.Context, source: str = typer.Option(None, "--source", "-s"),
                 domain: str = Opt.domain(), timeout: int = Opt.timeout(),
                 format: str = Opt.format(), columns: list[str] = Opt.columns()) -> None:
    params = {}
    if source:
        params["source"] = source
    if domain:
        params["domain"] = domain
    r = _client(ctx, format, timeout).request("GET", "/api/forwardings", params=params or None)
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@forward_app.command("add", help="Add a forwarding")
def forward_add(ctx: typer.Context, source: str = typer.Argument(...),
                destination: str = typer.Argument(...),
                keep_copy: bool = typer.Option(False, "--keep-copy/--no-keep-copy"),
                timeout: int = Opt.timeout(), format: str = Opt.format(),
                columns: list[str] = Opt.columns()) -> None:
    body = {"source": source, "destination": destination, "keep_copy": keep_copy}
    r = _client(ctx, format, timeout).request("POST", "/api/forwardings", json_body=body)
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@forward_app.command("rm", help="Delete a forwarding by id")
def forward_rm(ctx: typer.Context, fid: int = typer.Argument(...),
               timeout: int = Opt.timeout(), format: str = Opt.format(),
               columns: list[str] = Opt.columns()) -> None:
    r = _client(ctx, format, timeout).request("DELETE", f"/api/forwardings/{fid}")
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


# ── sendas ────────────────────────────────────────────────────────────────────
@sendas_app.command("list", help="List send-as grants")
def sendas_list(ctx: typer.Context, domain: str = Opt.domain(), timeout: int = Opt.timeout(),
                format: str = Opt.format(), columns: list[str] = Opt.columns()) -> None:
    params = {"domain": domain} if domain else None
    r = _client(ctx, format, timeout).request("GET", "/api/sender-logins", params=params)
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@sendas_app.command("grant", help="Grant: login_email may send AS allowed_sender")
def sendas_grant(ctx: typer.Context, login_email: str = typer.Argument(...),
                 allowed_sender: str = typer.Argument(...),
                 timeout: int = Opt.timeout(), format: str = Opt.format(),
                 columns: list[str] = Opt.columns()) -> None:
    body = {"login_email": login_email, "allowed_sender": allowed_sender}
    r = _client(ctx, format, timeout).request("POST", "/api/sender-logins", json_body=body)
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


@sendas_app.command("revoke", help="Revoke a send-as grant by id")
def sendas_revoke(ctx: typer.Context, sid: int = typer.Argument(...),
                  timeout: int = Opt.timeout(), format: str = Opt.format(),
                  columns: list[str] = Opt.columns()) -> None:
    r = _client(ctx, format, timeout).request("DELETE", f"/api/sender-logins/{sid}")
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


# ── audit ─────────────────────────────────────────────────────────────────────
@app.command(help="Read the audit log")
def audit(ctx: typer.Context, login: str = typer.Option(None, "--login"),
          event_type: str = typer.Option(None, "--type"),
          since: str = typer.Option(None, "--since"),
          limit: int = typer.Option(100, "--limit"),
          timeout: int = Opt.timeout(), format: str = Opt.format(),
          columns: list[str] = Opt.columns()) -> None:
    params = {"limit": limit}
    if login:
        params["login"] = login
    if event_type:
        params["event_type"] = event_type
    if since:
        params["since"] = since
    r = _client(ctx, format, timeout).request("GET", "/api/audit", params=params)
    CmdResult.from_response(r).render_and_exit(ctx.info_name, columns)


if __name__ == "__main__":
    app()
