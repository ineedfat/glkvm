# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    Copyright (C) 2018-2024  Maxim Devaev <mdevaev@gmail.com>               #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
# ========================================================================== #

"""MCP endpoint and pairing management for the RMQ1 KVMD service."""

import asyncio
import base64
import contextlib
import dataclasses
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import stat
import time
import uuid
from collections import OrderedDict
from typing import Any

from aiohttp.web import Request
from aiohttp.web import Response

from ....errors import IsBusyError
from ....htserver import BadRequestError
from ....htserver import ForbiddenError
from ....htserver import HttpError
from ....htserver import NotFoundError
from ....htserver import UnauthorizedError
from ....htserver import UnavailableError
from ....htserver import exposed_http
from ....keyboard.keysym import build_symmap
from ....keyboard.mappings import WEB_TO_EVDEV
from ....keyboard.printer import text_to_evdev_keys
from ....logging import get_logger
from ....mouse import MOUSE_TO_EVDEV
from ....plugins.atx import BaseAtx
from ....plugins.hid import BaseHid
from ....plugins.msd import BaseMsd
from ....validators.hid import valid_hid_key
from ....validators.hid import valid_hid_mouse_button
from ....validators.kvm import valid_msd_image_name
from ....validators.kvm import valid_msd_mount_name

from .config_utils import read_yaml
from .config_utils import set_nested_value
from .config_utils import write_yaml


_CONFIG_PATH = "/etc/kvmd/user/boot.yaml"
_AGENTS_PATH = "/etc/kvmd/user/mcp_agents.json"
_MCP_VERSION = "2026-07-28"
_LEGACY_VERSION = "2025-11-25"
_SUPPORTED_VERSIONS = [_MCP_VERSION, _LEGACY_VERSION]
_PAIR_TTL = 300
_UPLOAD_TTL = 900
_REQUEST_ID_TTL = 900
_REQUEST_ID_LIMIT = 4096
_MAX_JSON_SIZE = 1024 * 1024
_DEFAULT_SETTINGS = {
    "enabled": False,
    "trusted_networks": [],
    "lease_timeout": 300,
    "max_upload_gb": 8,
}


class McpProtocolError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


@dataclasses.dataclass
class _LegacySession:
    agent_id: str
    created: float
    last_seen: float
    seen_ids: OrderedDict[str, float]


@dataclasses.dataclass
class _Lease:
    agent_id: str
    session_id: str
    lease_id: str
    last_activity: float
    held_keys: set[int] = dataclasses.field(default_factory=set)
    held_buttons: set[int] = dataclasses.field(default_factory=set)


class McpApi:
    """MCP server registered in KVMD's authenticated aiohttp router."""

    def __init__(
        self,
        hid: BaseHid,
        atx: BaseAtx,
        msd: BaseMsd,
        streamer: Any,
        keymap_path: str,
    ) -> None:
        self.__hid = hid
        self.__atx = atx
        self.__msd = msd
        self.__streamer = streamer
        self.__logger = get_logger(0)
        self.__agents_lock = asyncio.Lock()
        self.__pairings_lock = asyncio.Lock()
        self.__sessions_lock = asyncio.Lock()
        self.__request_ids_lock = asyncio.Lock()
        self.__lease_lock = asyncio.Lock()
        self.__upload_lock = asyncio.Lock()
        self.__pairings: dict[str, dict] = {}
        self.__sessions: dict[str, _LegacySession] = {}
        self.__request_ids: dict[str, OrderedDict[str, float]] = {}
        self.__uploads: dict[str, dict] = {}
        self.__lease: (_Lease | None) = None
        self.__symmap = build_symmap(keymap_path)
        self.__tools = self.__make_tools()

    # ------------------------------------------------------------------ HTTP

    @exposed_http("POST", "/mcp", auth_required=False, allow_usc=False)
    async def __mcp_post_handler(self, req: Request) -> Response:
        try:
            agent = await self.__authorize_mcp_request(req)
            if req.content_length is not None and req.content_length > _MAX_JSON_SIZE:
                raise BadRequestError("MCP request exceeds the 1 MiB request limit")
            try:
                body = await req.json()
            except Exception as ex:
                raise BadRequestError("Invalid JSON request body") from ex
            if isinstance(body, list) or not isinstance(body, dict):
                raise McpProtocolError(-32600, "Expected one JSON-RPC message")
            return await self.__dispatch_mcp(req, agent, body)
        except McpProtocolError as ex:
            return self.__rpc_response({"jsonrpc": "2.0", "id": None, "error": self.__rpc_error_obj(ex)})
        except HttpError as ex:
            return Response(status=ex.status, text=str(ex), content_type="text/plain")
        except Exception as ex:  # Keep implementation details out of tool responses.
            self.__logger.exception("MCP request failed: %s", ex)
            return self.__rpc_response({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": "Internal error"},
            })

    @exposed_http("GET", "/mcp", auth_required=False, allow_usc=False)
    async def __mcp_get_handler(self, req: Request) -> Response:
        try:
            await self.__check_mcp_network(req)
        except HttpError as ex:
            return Response(status=ex.status, text=str(ex), content_type="text/plain")
        return Response(status=405, headers={"Allow": "POST, DELETE"})

    @exposed_http("DELETE", "/mcp", auth_required=False, allow_usc=False)
    async def __mcp_delete_handler(self, req: Request) -> Response:
        try:
            agent = await self.__authorize_mcp_request(req)
        except HttpError as ex:
            return Response(status=ex.status, text=str(ex), content_type="text/plain")
        session_id = req.headers.get("Mcp-Session-Id", "")
        async with self.__sessions_lock:
            session = self.__sessions.get(session_id)
            if session and session.agent_id == agent["id"]:
                del self.__sessions[session_id]
        return Response(status=200)

    @exposed_http("POST", "/mcp/upload", auth_required=False, allow_usc=False)
    async def __upload_handler(self, req: Request) -> Response:
        try:
            agent = await self.__authorize_mcp_request(req)
            upload_id = req.query.get("upload_id", "")
            upload_token = req.headers.get("Mcp-Upload-Token", "")
            if not upload_id or not upload_token:
                raise BadRequestError("upload_id and Mcp-Upload-Token are required")
            size = req.content_length
            if size is None or size <= 0:
                raise BadRequestError("A non-empty Content-Length is required")

            settings = await self.__get_settings()
            if size > int(settings["max_upload_gb"]) * 1024 ** 3:
                raise BadRequestError("Upload exceeds the configured maximum size")

            await self.__require_lease(agent["id"], self.__uploads.get(upload_id, {}).get("lease_id", ""))
            async with self.__upload_lock:
                upload = self.__uploads.get(upload_id)
                if (
                    not upload
                    or upload["agent_id"] != agent["id"]
                    or upload["used"]
                    or upload["expires"] < time.monotonic()
                    or not hmac.compare_digest(upload["token_hash"], self.__hash(upload_token))
                    or upload["size"] != size
                ):
                    raise ForbiddenError("Upload ticket is invalid, expired, or already used")
                upload["used"] = True

            written = 0
            async with self.__msd.write_image(upload["name"], size, True) as writer:
                chunk_size = writer.get_chunk_size()
                while True:
                    chunk = await req.content.read(chunk_size)
                    if not chunk:
                        break
                    if not await self.__touch_lease(agent["id"], upload["lease_id"]):
                        raise ForbiddenError("The controller lease was released during upload")
                    written += await writer.write_chunk(chunk)
            if written != size:
                raise BadRequestError("Uploaded byte count did not match Content-Length")
            async with self.__upload_lock:
                self.__uploads.pop(upload_id, None)
            await self.__touch_lease(agent["id"], upload["lease_id"])
            return self.__json_response({"ok": True, "image": upload["name"], "size": written})
        except HttpError as ex:
            return Response(status=ex.status, text=str(ex), content_type="text/plain")
        except Exception as ex:
            self.__logger.exception("MCP media upload failed: %s", ex)
            return Response(status=400, text="Media upload failed", content_type="text/plain")

    @exposed_http("POST", "/mcp/pair/start", auth_required=False, allow_usc=False)
    async def __pair_start_handler(self, req: Request) -> Response:
        try:
            ip = await self.__check_mcp_network(req)
            body = await req.json()
            name = self.__valid_agent_name(body.get("name", ""))
            async with self.__pairings_lock:
                self.__prune_pairings()
                if len(self.__pairings) >= 20:
                    raise IsBusyError("Too many pending pairing requests")
                pairing_id = secrets.token_urlsafe(24)
                poll_secret = secrets.token_urlsafe(32)
                code = f"{secrets.randbelow(1000000):06d}"
                self.__pairings[pairing_id] = {
                    "id": pairing_id,
                    "secret_hash": self.__hash(poll_secret),
                    "code": code,
                    "name": name,
                    "ip": ip,
                    "created": time.time(),
                    "expires": time.monotonic() + _PAIR_TTL,
                    "status": "pending",
                }
            return self.__json_response({
                "pairing_id": pairing_id,
                "poll_secret": poll_secret,
                "verification_code": code,
                "expires_in": _PAIR_TTL,
                "poll_interval": 2,
            })
        except HttpError as ex:
            return Response(status=ex.status, text=str(ex), content_type="text/plain")
        except Exception as ex:
            self.__logger.exception("MCP pairing request failed: %s", ex)
            return Response(status=400, text="Invalid pairing request", content_type="text/plain")

    @exposed_http("POST", "/mcp/pair/poll", auth_required=False, allow_usc=False)
    async def __pair_poll_handler(self, req: Request) -> Response:
        try:
            await self.__check_mcp_network(req)
            body = await req.json()
            pairing_id = str(body.get("pairing_id", ""))
            poll_secret = str(body.get("poll_secret", ""))
            async with self.__pairings_lock:
                self.__prune_pairings()
                pairing = self.__pairings.get(pairing_id)
                if (
                    not pairing
                    or not hmac.compare_digest(pairing["secret_hash"], self.__hash(poll_secret))
                ):
                    raise NotFoundError("Pairing request not found or expired")
                if pairing["status"] == "pending":
                    return self.__json_response({"status": "pending"})
                if pairing["status"] == "denied":
                    del self.__pairings[pairing_id]
                    return self.__json_response({"status": "denied"})

                if pairing["status"] == "approved":
                    token = "mcp_" + secrets.token_urlsafe(40)
                    agent = {
                        "id": str(uuid.uuid4()),
                        "name": pairing["name"],
                        "token_hash": self.__hash(token),
                        "enabled": True,
                        "created_at": int(time.time()),
                        "last_seen": None,
                    }
                    async with self.__agents_lock:
                        store = self.__read_agents()
                        store["agents"].append(agent)
                        self.__write_agents(store)
                    pairing["agent"] = agent
                    pairing["token"] = token
                    pairing["status"] = "issued"
                    self.__logger.info("MCP agent paired: %s (%s)", agent["name"], agent["id"])
                else:
                    agent = pairing["agent"]
                    token = pairing["token"]
            return self.__json_response({"status": "approved", "token": token, "agent_id": agent["id"]})
        except HttpError as ex:
            return Response(status=ex.status, text=str(ex), content_type="text/plain")
        except Exception as ex:
            self.__logger.exception("MCP pairing poll failed: %s", ex)
            return Response(status=400, text="Invalid pairing poll", content_type="text/plain")

    # ------------------------------------------------------------ Admin UI API

    @exposed_http("GET", "/mcp/admin/state")
    async def __admin_state_handler(self, _: Request) -> Response:
        return self.__json_response(await self.__admin_state())

    @exposed_http("POST", "/mcp/admin/settings")
    async def __admin_settings_handler(self, req: Request) -> Response:
        body = await req.json()
        settings = self.__validate_settings(body)
        raw = await read_yaml(_CONFIG_PATH)
        set_nested_value(raw, "kvmd/mcp", settings)
        await write_yaml(raw, _CONFIG_PATH)
        if not settings["enabled"]:
            await self.__clear_lease()
        return self.__json_response(await self.__admin_state())

    @exposed_http("POST", "/mcp/admin/pairings/approve")
    async def __admin_pair_approve_handler(self, req: Request) -> Response:
        body = await req.json()
        pairing_id = str(body.get("pairing_id", ""))
        async with self.__pairings_lock:
            self.__prune_pairings()
            pairing = self.__pairings.get(pairing_id)
            if not pairing or pairing["status"] != "pending":
                raise NotFoundError("Pending pairing request not found")
            pairing["status"] = "approved"
            pairing["approved_at"] = int(time.time())
        return self.__json_response({"ok": True})

    @exposed_http("POST", "/mcp/admin/pairings/deny")
    async def __admin_pair_deny_handler(self, req: Request) -> Response:
        body = await req.json()
        pairing_id = str(body.get("pairing_id", ""))
        async with self.__pairings_lock:
            self.__prune_pairings()
            pairing = self.__pairings.get(pairing_id)
            if not pairing or pairing["status"] != "pending":
                raise NotFoundError("Pending pairing request not found")
            pairing["status"] = "denied"
        return self.__json_response({"ok": True})

    @exposed_http("POST", "/mcp/admin/agents/toggle")
    async def __admin_agent_toggle_handler(self, req: Request) -> Response:
        body = await req.json()
        agent_id = str(body.get("agent_id", ""))
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            raise BadRequestError("enabled must be a boolean")
        async with self.__agents_lock:
            store = self.__read_agents()
            agent = next((item for item in store["agents"] if item["id"] == agent_id), None)
            if not agent:
                raise NotFoundError("Paired agent not found")
            agent["enabled"] = enabled
            self.__write_agents(store)
        if not enabled:
            await self.__clear_lease(agent_id)
            async with self.__sessions_lock:
                self.__sessions = {
                    sid: session for sid, session in self.__sessions.items()
                    if session.agent_id != agent_id
                }
        return self.__json_response(await self.__admin_state())

    # ------------------------------------------------------------------ MCP

    async def __dispatch_mcp(self, req: Request, agent: dict, body: dict) -> Response:
        if body.get("jsonrpc") != "2.0" or not isinstance(body.get("method"), str):
            raise McpProtocolError(-32600, "Invalid JSON-RPC request")
        method = body["method"]
        request_id = body.get("id")
        if request_id is None:
            if method.startswith("notifications/"):
                return Response(status=202)
            raise McpProtocolError(-32600, "Request id is required")
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
            raise McpProtocolError(-32600, "Request id must be a string or integer")

        params = body.get("params", {})
        if not isinstance(params, dict):
            raise McpProtocolError(-32602, "params must be an object")
        modern = await self.__validate_protocol(req, body, method, params)
        session_id = ""
        response_headers: dict[str, str] = {}

        if method == "initialize":
            if modern:
                raise McpProtocolError(-32601, "initialize is not used by the stateless MCP protocol")
            session_id = secrets.token_urlsafe(24)
            now = time.monotonic()
            async with self.__sessions_lock:
                self.__sessions[session_id] = _LegacySession(agent["id"], now, now, OrderedDict())
            response_headers["Mcp-Session-Id"] = session_id
            result = {
                "protocolVersion": _LEGACY_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "glkvm-rmq1", "version": "1.0.0"},
                "instructions": self.__instructions(),
            }
            return self.__rpc_result(request_id, result, headers=response_headers)

        if method == "server/discover":
            if not modern:
                raise McpProtocolError(-32601, "server/discover requires protocol 2026-07-28")
            result = {
                "resultType": "complete",
                "supportedProtocolVersions": _SUPPORTED_VERSIONS,
                "capabilities": {"tools": {}},
                "instructions": self.__instructions(),
            }
            return self.__rpc_result(request_id, result, meta={"io.modelcontextprotocol/serverInfo": {
                "name": "glkvm-rmq1", "version": "1.0.0",
            }})

        if not modern:
            session_id = req.headers.get("Mcp-Session-Id", "")
            if not session_id:
                raise McpProtocolError(-32600, "Mcp-Session-Id is required")
            async with self.__sessions_lock:
                session = self.__sessions.get(session_id)
                if not session or session.agent_id != agent["id"]:
                    raise McpProtocolError(-32001, "Session not found")
                session.last_seen = time.monotonic()
                if self.__has_seen(session.seen_ids, request_id):
                    raise McpProtocolError(-32600, "Duplicate request id rejected")
                self.__remember_id(session.seen_ids, request_id)
            response_headers["Mcp-Session-Id"] = session_id
        else:
            if await self.__modern_id_replayed(agent["id"], request_id):
                raise McpProtocolError(-32600, "Duplicate request id rejected for this agent")

        if method == "notifications/initialized":
            return Response(status=202, headers=response_headers)
        if method == "ping":
            result = {} if not modern else {"resultType": "complete"}
            return self.__rpc_result(request_id, result, headers=response_headers)
        if method == "tools/list":
            result = {"tools": self.__tools}
            if modern:
                result.update({"resultType": "complete", "ttlMs": 60000, "cacheScope": "private"})
            return self.__rpc_result(request_id, result, headers=response_headers)
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not isinstance(arguments, dict):
                raise McpProtocolError(-32602, "tools/call requires name and object arguments")
            try:
                content = await self.__call_tool(name, arguments, agent, session_id)
                result = {"content": content, "isError": False}
            except (BadRequestError, ForbiddenError, NotFoundError, UnavailableError, IsBusyError) as ex:
                result = {"content": [{"type": "text", "text": str(ex)}], "isError": True}
            except Exception as ex:
                self.__logger.exception("MCP tool %s failed: %s", name, ex)
                result = {"content": [{"type": "text", "text": "Tool execution failed"}], "isError": True}
            if modern:
                result["resultType"] = "complete"
            return self.__rpc_result(request_id, result, headers=response_headers)
        if method.startswith("notifications/"):
            return Response(status=202, headers=response_headers)
        raise McpProtocolError(-32601, f"Method not found: {method}")

    async def __validate_protocol(self, req: Request, body: dict, method: str, params: dict) -> bool:
        meta = params.get("_meta", {})
        modern_version = ""
        if isinstance(meta, dict):
            modern_version = meta.get("io.modelcontextprotocol/protocolVersion", "")
        header_version = req.headers.get("Mcp-Protocol-Version", "")
        modern = bool(modern_version or header_version == _MCP_VERSION or method == "server/discover")
        if modern:
            if modern_version != _MCP_VERSION or header_version != _MCP_VERSION:
                raise McpProtocolError(-32022, "Unsupported or mismatched MCP protocol version", {
                    "supported": _SUPPORTED_VERSIONS,
                    "requested": modern_version or header_version,
                })
            if req.headers.get("Mcp-Method", "") != method:
                raise McpProtocolError(-32020, "Mcp-Method header does not match request method")
            if method == "tools/call" and req.headers.get("Mcp-Name", "") != params.get("name", ""):
                raise McpProtocolError(-32020, "Mcp-Name header does not match requested tool")
            if method == "server/discover":
                return True
            client_info = meta.get("io.modelcontextprotocol/clientInfo") if isinstance(meta, dict) else None
            if not isinstance(client_info, dict) or not isinstance(client_info.get("name"), str):
                raise McpProtocolError(-32602, "Modern requests must include clientInfo metadata")
            capabilities = meta.get("io.modelcontextprotocol/clientCapabilities")
            if not isinstance(capabilities, dict):
                raise McpProtocolError(-32602, "Modern requests must include clientCapabilities metadata")
            return True
        if header_version and header_version not in _SUPPORTED_VERSIONS:
            raise McpProtocolError(-32022, "Unsupported MCP protocol version", {
                "supported": _SUPPORTED_VERSIONS, "requested": header_version,
            })
        if method == "initialize":
            requested = params.get("protocolVersion", _LEGACY_VERSION)
            if requested not in _SUPPORTED_VERSIONS:
                raise McpProtocolError(-32022, "Unsupported MCP protocol version", {
                    "supported": _SUPPORTED_VERSIONS, "requested": requested,
                })
        return False

    async def __call_tool(self, name: str, args: dict, agent: dict, session_id: str) -> list[dict]:
        if name == "get_screenshot":
            snapshot = await self.__streamer.take_snapshot(save=False, load=False, allow_offline=False)
            if not snapshot:
                raise UnavailableError("No screenshot is available")
            return [{"type": "image", "data": base64.b64encode(snapshot.data).decode("ascii"), "mimeType": "image/jpeg"}]

        if name == "acquire_control":
            return [self.__text(await self.__acquire_lease(agent["id"], session_id))]
        if name == "release_control":
            await self.__release_lease(agent["id"], str(args.get("lease_id", "")))
            return [self.__text("Control lease released")]

        lease_id = str(args.get("lease_id", ""))
        await self.__require_lease(agent["id"], lease_id)

        if name == "type_text":
            text = self.__string(args, "text", 8192)
            await self.__hid.send_key_events(text_to_evdev_keys(text, self.__symmap), no_ignore_keys=True)
            await self.__touch_lease(agent["id"], lease_id)
            return [self.__text("Text typed")]

        if name == "press_keys":
            keys = args.get("keys")
            if not isinstance(keys, list) or not keys or len(keys) > 8:
                raise BadRequestError("keys must contain 1 to 8 key names")
            codes = [WEB_TO_EVDEV[valid_hid_key(key)] for key in keys]
            try:
                for code in codes:
                    self.__hid.send_key_event(code, True, False)
                await asyncio.sleep(0.03)
            finally:
                for code in reversed(codes):
                    self.__hid.send_key_event(code, False, False)
            await self.__touch_lease(agent["id"], lease_id)
            return [self.__text("Key combination pressed")]

        if name == "key_event":
            key = valid_hid_key(self.__string(args, "key", 64))
            pressed = args.get("pressed")
            if not isinstance(pressed, bool):
                raise BadRequestError("pressed must be a boolean")
            code = WEB_TO_EVDEV[key]
            self.__hid.send_key_event(code, pressed, False)
            await self.__track_held_key(agent["id"], lease_id, code, pressed)
            return [self.__text("Key state updated")]

        if name == "move_mouse":
            x = self.__integer(args, "x")
            y = self.__integer(args, "y")
            width = self.__integer(args, "screen_width")
            height = self.__integer(args, "screen_height")
            self.__hid.send_mouse_move_event(
                self.__pixel_to_hid(x, width), self.__pixel_to_hid(y, height),
            )
            await self.__touch_lease(agent["id"], lease_id)
            return [self.__text("Mouse moved")]

        if name == "mouse_button":
            button = self.__string(args, "button", 16)
            if button not in MOUSE_TO_EVDEV:
                raise BadRequestError("button must be left, right, middle, up, or down")
            pressed = args.get("pressed")
            if not isinstance(pressed, bool):
                raise BadRequestError("pressed must be a boolean")
            code = MOUSE_TO_EVDEV[valid_hid_mouse_button(button)]
            self.__hid.send_mouse_button_event(code, pressed)
            await self.__track_held_button(agent["id"], lease_id, code, pressed)
            return [self.__text("Mouse button state updated")]

        if name == "click":
            x = self.__integer(args, "x")
            y = self.__integer(args, "y")
            width = self.__integer(args, "screen_width")
            height = self.__integer(args, "screen_height")
            button = self.__string(args, "button", 16)
            if button not in MOUSE_TO_EVDEV:
                raise BadRequestError("button must be left, right, middle, up, or down")
            count = args.get("count", 1)
            if isinstance(count, bool) or count not in (1, 2, 3):
                raise BadRequestError("count must be 1, 2, or 3")
            self.__hid.send_mouse_move_event(self.__pixel_to_hid(x, width), self.__pixel_to_hid(y, height))
            code = MOUSE_TO_EVDEV[button]
            for _ in range(count):
                self.__hid.send_mouse_button_event(code, True)
                await asyncio.sleep(0.04)
                self.__hid.send_mouse_button_event(code, False)
                if count > 1:
                    await asyncio.sleep(0.08)
            await self.__touch_lease(agent["id"], lease_id)
            return [self.__text("Mouse click sent")]

        if name == "scroll_mouse":
            dx = self.__integer(args, "delta_x")
            dy = self.__integer(args, "delta_y")
            if not -2048 <= dx <= 2048 or not -2048 <= dy <= 2048:
                raise BadRequestError("scroll deltas must be between -2048 and 2048")
            self.__hid.send_mouse_wheel_event(dx, dy)
            await self.__touch_lease(agent["id"], lease_id)
            return [self.__text("Mouse scrolled")]

        if name == "release_all_input":
            await self.__release_held(agent["id"], lease_id)
            await self.__touch_lease(agent["id"], lease_id)
            return [self.__text("All held keys and mouse buttons released")]

        if name == "power_control":
            action = self.__string(args, "action", 32)
            wait = args.get("wait", False)
            if not isinstance(wait, bool):
                raise BadRequestError("wait must be a boolean")
            actions = {
                "power_on": self.__atx.power_on,
                "power_off": self.__atx.power_off,
                "power_off_hard": self.__atx.power_off_hard,
                "reset_hard": self.__atx.power_reset_hard,
                "press_power": self.__atx.click_power,
                "hold_power": self.__atx.click_power_long,
                "press_reset": self.__atx.click_reset,
            }
            if action not in actions:
                raise BadRequestError("Unsupported power action")
            await actions[action](wait)
            await self.__touch_lease(agent["id"], lease_id)
            return [self.__text(f"Power action completed: {action}")]

        if name == "list_media":
            state = await self.__msd.get_state()
            storage = state.get("storage", {}) if isinstance(state, dict) else {}
            images = storage.get("images", []) if isinstance(storage, dict) else []
            return [self.__text(json.dumps({"images": images}, ensure_ascii=False))]

        if name == "begin_media_upload":
            image_name = valid_msd_image_name(self.__string(args, "image_name", 240))
            size = self.__integer(args, "size_bytes")
            if size <= 0:
                raise BadRequestError("size_bytes must be greater than zero")
            settings = await self.__get_settings()
            if size > int(settings["max_upload_gb"]) * 1024 ** 3:
                raise BadRequestError("Image exceeds the configured upload limit")
            state = await self.__msd.get_state()
            free = self.__get_free_space(state)
            if free is not None and size > free:
                raise BadRequestError("Image is larger than the available virtual media storage")
            upload_id = secrets.token_urlsafe(24)
            upload_token = secrets.token_urlsafe(32)
            async with self.__upload_lock:
                self.__prune_uploads()
                self.__uploads[upload_id] = {
                    "agent_id": agent["id"],
                    "lease_id": lease_id,
                    "token_hash": self.__hash(upload_token),
                    "name": image_name,
                    "size": size,
                    "expires": time.monotonic() + _UPLOAD_TTL,
                    "used": False,
                }
            await self.__touch_lease(agent["id"], lease_id)
            return [self.__text(json.dumps({
                "upload_id": upload_id,
                "upload_path": f"/mcp/upload?upload_id={upload_id}",
                "upload_token": upload_token,
                "method": "POST",
                "expires_in": _UPLOAD_TTL,
                "headers": {"Authorization": "Bearer <paired-token>", "Mcp-Upload-Token": upload_token},
                "body": "Raw image bytes; Content-Length must exactly match size_bytes.",
            }))]

        if name == "mount_media":
            image_name = valid_msd_mount_name(self.__string(args, "image_name", 240))
            cdrom = args.get("cdrom", True)
            read_only = args.get("read_only", True)
            if not isinstance(cdrom, bool) or not isinstance(read_only, bool):
                raise BadRequestError("cdrom and read_only must be booleans")
            await self.__msd.set_params(name=image_name, cdrom=cdrom, rw=not read_only)
            await self.__msd.set_connected(True)
            await self.__touch_lease(agent["id"], lease_id)
            return [self.__text(f"Mounted {image_name}")]

        if name == "eject_media":
            await self.__msd.set_connected(False)
            await self.__touch_lease(agent["id"], lease_id)
            return [self.__text("Virtual media ejected")]

        raise McpProtocolError(-32602, f"Unknown tool: {name}")

    # ------------------------------------------------------------- Tool schema

    @staticmethod
    def __make_tools() -> list[dict]:
        def tool(name: str, description: str, properties: dict | None = None, required: list[str] | None = None, destructive: bool = False) -> dict:
            schema: dict = {"type": "object", "properties": properties or {}, "additionalProperties": False}
            if required:
                schema["required"] = required
            return {
                "name": name,
                "description": description,
                "inputSchema": schema,
                "annotations": {"readOnlyHint": False, "destructiveHint": destructive, "openWorldHint": False},
            }

        lease = {"lease_id": {"type": "string", "description": "Control lease returned by acquire_control"}}
        return [
            tool("get_screenshot", "Return the current physical computer screen as a JPEG image."),
            tool("acquire_control", "Acquire exclusive keyboard, mouse, virtual media, and power control. The lease expires after five minutes without a control action.", destructive=True),
            tool("release_control", "Release the exclusive controller lease.", {**lease}, ["lease_id"]),
            tool("type_text", "Type text using the configured keyboard layout.", {**lease, "text": {"type": "string", "maxLength": 8192}}, ["lease_id", "text"], True),
            tool("press_keys", "Press a key or key combination, then release it. Use key names from the KVMD keymap such as KEY_ENTER or KEY_LEFTCTRL.", {**lease, "keys": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 8}}, ["lease_id", "keys"], True),
            tool("key_event", "Hold or release a single keyboard key. Call with pressed=false to release a held key.", {**lease, "key": {"type": "string"}, "pressed": {"type": "boolean"}}, ["lease_id", "key", "pressed"], True),
            tool("move_mouse", "Move to pixel coordinates from a screenshot. Supply the screenshot width and height.", {**lease, "x": {"type": "integer"}, "y": {"type": "integer"}, "screen_width": {"type": "integer", "minimum": 1}, "screen_height": {"type": "integer", "minimum": 1}}, ["lease_id", "x", "y", "screen_width", "screen_height"], True),
            tool("mouse_button", "Press or release a mouse button. Supports left, right, middle, up, and down.", {**lease, "button": {"type": "string"}, "pressed": {"type": "boolean"}}, ["lease_id", "button", "pressed"], True),
            tool("click", "Click at pixel coordinates from a screenshot; supports single, double, or triple click.", {**lease, "x": {"type": "integer"}, "y": {"type": "integer"}, "screen_width": {"type": "integer", "minimum": 1}, "screen_height": {"type": "integer", "minimum": 1}, "button": {"type": "string"}, "count": {"type": "integer", "enum": [1, 2, 3]}}, ["lease_id", "x", "y", "screen_width", "screen_height", "button"], True),
            tool("scroll_mouse", "Scroll vertically or horizontally using relative wheel deltas.", {**lease, "delta_x": {"type": "integer"}, "delta_y": {"type": "integer"}}, ["lease_id", "delta_x", "delta_y"], True),
            tool("release_all_input", "Release all keys and mouse buttons held by the current controller.", {**lease}, ["lease_id"], True),
            tool("power_control", "Control target power or reset. These actions are issued immediately without confirmation.", {**lease, "action": {"type": "string", "enum": ["power_on", "power_off", "power_off_hard", "reset_hard", "press_power", "hold_power", "press_reset"]}, "wait": {"type": "boolean"}}, ["lease_id", "action"], True),
            tool("list_media", "List virtual media images already stored on the RMQ1.", {**lease}, ["lease_id"]),
            tool("begin_media_upload", "Create a one-time raw HTTP upload ticket for a disk image. Use the returned upload_path and headers to POST the raw file bytes before the ticket expires.", {**lease, "image_name": {"type": "string"}, "size_bytes": {"type": "integer", "minimum": 1}}, ["lease_id", "image_name", "size_bytes"], True),
            tool("mount_media", "Mount a stored virtual media image to the controlled computer.", {**lease, "image_name": {"type": "string"}, "cdrom": {"type": "boolean"}, "read_only": {"type": "boolean"}}, ["lease_id", "image_name"], True),
            tool("eject_media", "Eject the currently connected virtual media.", {**lease}, ["lease_id"], True),
        ]

    # --------------------------------------------------------------- Security

    async def __authorize_mcp_request(self, req: Request) -> dict:
        await self.__check_mcp_network(req)
        authorization = req.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            raise UnauthorizedError("MCP paired token required")
        token = authorization[7:].strip()
        if not token or len(token) > 256:
            raise UnauthorizedError("Invalid MCP token")
        token_hash = self.__hash(token)
        async with self.__agents_lock:
            store = self.__read_agents()
            agent = next((
                item for item in store["agents"]
                if hmac.compare_digest(item["token_hash"], token_hash)
            ), None)
            if not agent or not agent.get("enabled", False):
                raise ForbiddenError("MCP agent is disabled or not paired")
            now = int(time.time())
            if agent.get("last_seen") is None or now - int(agent["last_seen"]) >= 60:
                agent["last_seen"] = now
                self.__write_agents(store)
            return dict(agent)

    async def __check_mcp_network(self, req: Request) -> str:
        settings = await self.__get_settings()
        if not settings["enabled"]:
            raise UnavailableError("MCP is disabled in KVMD settings")
        transport = req.transport
        peer_socket = transport.get_extra_info("socket") if transport else None
        if peer_socket and peer_socket.family == socket.AF_UNIX:
            trusted_proxy = True
        else:
            try:
                peer_ip = ipaddress.ip_address(req.remote or "")
            except ValueError:
                raise ForbiddenError("Unable to determine proxy connection")
            trusted_proxy = peer_ip.is_loopback
        forwarded_proto = req.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower() if trusted_proxy else ""
        effective_scheme = forwarded_proto or req.scheme
        if effective_scheme != "https":
            raise ForbiddenError("MCP requires HTTPS")
        raw_ip = (req.headers.get("X-Real-IP", "").strip() if trusted_proxy else "") or (req.remote or "")
        try:
            remote_ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            raise ForbiddenError("Unable to determine client IP")
        networks = []
        for value in settings["trusted_networks"]:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
        if not networks or not any(remote_ip in network for network in networks):
            raise ForbiddenError("Client IP is outside the configured trusted networks")
        return str(remote_ip)

    async def __get_settings(self) -> dict:
        raw = await read_yaml(_CONFIG_PATH)
        current = raw
        for key in ["kvmd", "mcp"]:
            if not isinstance(current, dict):
                current = {}
                break
            current = current.get(key, {})
        settings = {**_DEFAULT_SETTINGS, **(current if isinstance(current, dict) else {})}
        return settings

    def __validate_settings(self, body: dict) -> dict:
        if not isinstance(body.get("enabled"), bool):
            raise BadRequestError("enabled must be a boolean")
        networks = body.get("trusted_networks", [])
        if isinstance(networks, str):
            networks = networks.replace(",", "\n").splitlines()
        if not isinstance(networks, list) or len(networks) > 100:
            raise BadRequestError("trusted_networks must be a list of up to 100 CIDRs")
        clean_networks = []
        for item in networks:
            text = str(item).strip()
            if not text:
                continue
            try:
                network = str(ipaddress.ip_network(text, strict=False))
            except ValueError:
                raise BadRequestError(f"Invalid IP network: {text}")
            if network not in clean_networks:
                clean_networks.append(network)
        idle = body.get("lease_timeout", 300)
        upload_gb = body.get("max_upload_gb", 8)
        if isinstance(idle, bool) or not isinstance(idle, int) or not 30 <= idle <= 3600:
            raise BadRequestError("lease_timeout must be between 30 and 3600 seconds")
        if isinstance(upload_gb, bool) or not isinstance(upload_gb, int) or not 1 <= upload_gb <= 64:
            raise BadRequestError("max_upload_gb must be between 1 and 64")
        if body["enabled"] and not clean_networks:
            raise BadRequestError("Add at least one trusted network before enabling MCP")
        return {
            "enabled": body["enabled"],
            "trusted_networks": clean_networks,
            "lease_timeout": idle,
            "max_upload_gb": upload_gb,
        }

    # ---------------------------------------------------------- Pairing/store

    async def __admin_state(self) -> dict:
        settings = await self.__get_settings()
        async with self.__agents_lock:
            agents = [
                {key: item.get(key) for key in ("id", "name", "enabled", "created_at", "last_seen")}
                for item in self.__read_agents()["agents"]
            ]
        async with self.__pairings_lock:
            self.__prune_pairings()
            pairings = [{
                "id": item["id"],
                "name": item["name"],
                "verification_code": item["code"],
                "ip": item["ip"],
                "created_at": item["created"],
                "expires_in": max(0, int(item["expires"] - time.monotonic())),
                "status": item["status"],
            } for item in self.__pairings.values()]
        async with self.__lease_lock:
            lease = None
            if self.__lease:
                lease = {
                    "agent_id": self.__lease.agent_id,
                    "expires_in": max(0, int(settings["lease_timeout"] - (time.monotonic() - self.__lease.last_activity))),
                }
        return {"settings": settings, "agents": agents, "pairings": pairings, "controller": lease}

    @staticmethod
    def __valid_agent_name(value: Any) -> str:
        name = str(value).strip()
        if not name or len(name) > 64 or any(ord(char) < 32 for char in name):
            raise BadRequestError("Agent name must contain 1 to 64 printable characters")
        return name

    def __prune_pairings(self) -> None:
        now = time.monotonic()
        for pairing_id in [key for key, item in self.__pairings.items() if item["expires"] <= now]:
            del self.__pairings[pairing_id]

    def __read_agents(self) -> dict:
        try:
            with open(_AGENTS_PATH, "r", encoding="utf-8") as file:
                data = json.load(file)
            if isinstance(data, dict) and isinstance(data.get("agents"), list):
                return data
        except FileNotFoundError:
            pass
        except Exception as ex:
            self.__logger.error("Cannot read MCP agent store: %s", ex)
        return {"agents": []}

    def __write_agents(self, data: dict) -> None:
        directory = os.path.dirname(_AGENTS_PATH)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(directory, 0o700)
        temporary = _AGENTS_PATH + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(data, file, separators=(",", ":"))
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, _AGENTS_PATH)
            os.chmod(_AGENTS_PATH, 0o600)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)

    @staticmethod
    def __hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    # --------------------------------------------------------------- Replay

    @staticmethod
    def __request_key(request_id: Any) -> str:
        return json.dumps(request_id, separators=(",", ":"), ensure_ascii=True)

    @staticmethod
    def __has_seen(cache: OrderedDict[str, float], request_id: Any) -> bool:
        key = McpApi.__request_key(request_id)
        now = time.monotonic()
        for old_key in [item for item, timestamp in cache.items() if now - timestamp > _REQUEST_ID_TTL]:
            cache.pop(old_key, None)
        return key in cache

    @staticmethod
    def __remember_id(cache: OrderedDict[str, float], request_id: Any) -> None:
        cache[McpApi.__request_key(request_id)] = time.monotonic()
        while len(cache) > _REQUEST_ID_LIMIT:
            cache.popitem(last=False)

    async def __modern_id_replayed(self, agent_id: str, request_id: Any) -> bool:
        async with self.__request_ids_lock:
            cache = self.__request_ids.setdefault(agent_id, OrderedDict())
            if self.__has_seen(cache, request_id):
                return True
            self.__remember_id(cache, request_id)
            return False

    # --------------------------------------------------------------- Leases

    async def __acquire_lease(self, agent_id: str, session_id: str) -> dict:
        settings = await self.__get_settings()
        async with self.__lease_lock:
            await self.__expire_lease_if_idle(int(settings["lease_timeout"]))
            if self.__lease:
                if self.__lease.agent_id == agent_id and self.__lease.session_id == session_id:
                    self.__lease.last_activity = time.monotonic()
                    return {"lease_id": self.__lease.lease_id, "expires_in": settings["lease_timeout"]}
                raise IsBusyError("Another agent currently controls the KVM")
            self.__lease = _Lease(agent_id, session_id, secrets.token_urlsafe(32), time.monotonic())
            return {"lease_id": self.__lease.lease_id, "expires_in": settings["lease_timeout"]}

    async def __require_lease(self, agent_id: str, lease_id: str) -> None:
        settings = await self.__get_settings()
        async with self.__lease_lock:
            await self.__expire_lease_if_idle(int(settings["lease_timeout"]))
            if not self.__lease or self.__lease.agent_id != agent_id or not hmac.compare_digest(self.__lease.lease_id, lease_id):
                raise IsBusyError("Acquire the exclusive control lease before changing the target")

    async def __touch_lease(self, agent_id: str, lease_id: str) -> bool:
        async with self.__lease_lock:
            if self.__lease and self.__lease.agent_id == agent_id and hmac.compare_digest(self.__lease.lease_id, lease_id):
                self.__lease.last_activity = time.monotonic()
                return True
            return False

    async def __track_held_key(self, agent_id: str, lease_id: str, code: int, pressed: bool) -> None:
        async with self.__lease_lock:
            if self.__lease and self.__lease.agent_id == agent_id and hmac.compare_digest(self.__lease.lease_id, lease_id):
                if pressed:
                    self.__lease.held_keys.add(code)
                else:
                    self.__lease.held_keys.discard(code)
                self.__lease.last_activity = time.monotonic()

    async def __track_held_button(self, agent_id: str, lease_id: str, code: int, pressed: bool) -> None:
        async with self.__lease_lock:
            if self.__lease and self.__lease.agent_id == agent_id and hmac.compare_digest(self.__lease.lease_id, lease_id):
                if pressed:
                    self.__lease.held_buttons.add(code)
                else:
                    self.__lease.held_buttons.discard(code)
                self.__lease.last_activity = time.monotonic()

    async def __release_held(self, agent_id: str, lease_id: str) -> None:
        async with self.__lease_lock:
            lease = self.__lease
            if not lease or lease.agent_id != agent_id or not hmac.compare_digest(lease.lease_id, lease_id):
                raise IsBusyError("Control lease not found")
            self.__release_inputs(lease)

    async def __release_lease(self, agent_id: str, lease_id: str) -> None:
        async with self.__lease_lock:
            lease = self.__lease
            if not lease or lease.agent_id != agent_id or not hmac.compare_digest(lease.lease_id, lease_id):
                raise NotFoundError("Control lease not found or expired")
            self.__release_inputs(lease)
            self.__lease = None

    async def __clear_lease(self, agent_id: str = "") -> None:
        async with self.__lease_lock:
            if self.__lease and (not agent_id or self.__lease.agent_id == agent_id):
                self.__release_inputs(self.__lease)
                self.__lease = None

    def __release_inputs(self, lease: _Lease) -> None:
        for key in list(lease.held_keys):
            self.__hid.send_key_event(key, False, False)
        for button in list(lease.held_buttons):
            self.__hid.send_mouse_button_event(button, False)
        lease.held_keys.clear()
        lease.held_buttons.clear()

    async def __expire_lease_if_idle(self, timeout: int) -> None:
        if self.__lease and time.monotonic() - self.__lease.last_activity >= timeout:
            self.__logger.info("MCP controller lease expired for agent %s", self.__lease.agent_id)
            self.__release_inputs(self.__lease)
            self.__lease = None

    async def systask(self) -> None:
        while True:
            settings = await self.__get_settings()
            async with self.__lease_lock:
                await self.__expire_lease_if_idle(int(settings["lease_timeout"]))
            await asyncio.sleep(5)

    async def cleanup(self) -> None:
        await self.__clear_lease()

    # --------------------------------------------------------------- Helpers

    @staticmethod
    def __rpc_error_obj(error: McpProtocolError) -> dict:
        result = {"code": error.code, "message": str(error)}
        if error.data is not None:
            result["data"] = error.data
        return result

    def __rpc_result(self, request_id: Any, result: dict, headers: dict | None = None, meta: dict | None = None) -> Response:
        value: dict = {"jsonrpc": "2.0", "id": request_id, "result": result}
        if meta:
            value["_meta"] = meta
        return self.__json_response(value, headers=headers)

    def __rpc_response(self, value: dict) -> Response:
        return self.__json_response(value)

    @staticmethod
    def __json_response(value: dict, headers: dict | None = None) -> Response:
        return Response(
            text=json.dumps(value, ensure_ascii=False, separators=(",", ":")),
            content_type="application/json",
            headers=headers,
        )

    @staticmethod
    def __text(text: str) -> dict:
        return {"type": "text", "text": text}

    @staticmethod
    def __instructions() -> str:
        return (
            "Use get_screenshot to observe the computer. Acquire the control lease before keyboard, "
            "mouse, virtual media, or power operations. Release it when finished. The lease expires "
            "after five minutes without a control action."
        )

    @staticmethod
    def __string(args: dict, name: str, max_length: int) -> str:
        value = args.get(name)
        if not isinstance(value, str) or len(value) > max_length:
            raise BadRequestError(f"{name} must be a string of at most {max_length} characters")
        return value

    @staticmethod
    def __integer(args: dict, name: str) -> int:
        value = args.get(name)
        if isinstance(value, bool) or not isinstance(value, int):
            raise BadRequestError(f"{name} must be an integer")
        return value

    @staticmethod
    def __pixel_to_hid(value: int, extent: int) -> int:
        if extent < 1 or value < 0 or value >= extent:
            raise BadRequestError("Mouse coordinates must fall inside the supplied screenshot dimensions")
        if extent == 1:
            return -32768
        return round(value * 65535 / (extent - 1)) - 32768

    @staticmethod
    def __get_free_space(state: dict) -> int | None:
        try:
            return int(state["storage"]["parts"][""]["free"])
        except (KeyError, TypeError, ValueError):
            return None

    def __prune_uploads(self) -> None:
        now = time.monotonic()
        for upload_id in [key for key, item in self.__uploads.items() if item["expires"] <= now or item["used"]]:
            del self.__uploads[upload_id]
