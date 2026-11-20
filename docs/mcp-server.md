# KVMD MCP server

The RMQ1 MCP endpoint is `https://<device-host>/mcp` and uses Streamable HTTP.
KVMD supports the stateless `2026-07-28` protocol plus legacy
`2025-11-25` sessions. Requests use a paired agent bearer token; they do not use
the KVMD password or browser session cookie.

## Enable and pair an agent

In the authenticated KVM web UI, open **System → MCP agents**. Add the client
network CIDR (including a VPN subnet when applicable), set the lease idle timeout
and upload limit, and enable MCP. Only HTTPS requests from a listed network are
accepted.

The agent starts pairing by sending `POST /mcp/pair/start` with a JSON body such
as `{"name":"my-agent"}`. The response includes `pairing_id`, `poll_secret`,
and a six-digit verification code. The user verifies the request name, code, and
source IP in **System → MCP agents**, then approves it. The requesting agent polls
`POST /mcp/pair/poll` with `pairing_id` and `poll_secret`; once approved, the
response supplies the paired token. The poll secret allows only polling that
specific pending request, which expires after five minutes. The verification code
is for the user to confirm the same request; it does not authorize pairing by
itself. Once approved, polling can be retried until expiry if the token response
was interrupted.

Paired agent tokens remain valid until an administrator turns that agent off.
Turning it back on restores its token. No password is returned to the agent.

## Control model

An agent can call `get_screenshot` without acquiring control. It must acquire the
single controller lease before other tools. A different agent receives a busy
response while the lease is held. The lease expires after five minutes idle by
default (configurable from 30 to 3600 seconds); releasing or expiring it releases
any held keys and mouse buttons.

Available tools cover screenshots, keyboard input, mouse movement/buttons/scroll,
power/reset, and virtual media list/upload/mount/eject. Media uploads use a
short-lived one-use upload ticket and a streamed raw HTTP request body, subject to
the configured limit and available device storage.

KVMD rejects duplicate JSON-RPC request IDs per paired agent (modern stateless
protocol) or per legacy MCP session during a 15-minute window. This limits
accidental replay but does not prevent reuse of a stolen active bearer token.
Proof-of-possession (DPoP) is a possible later hardening feature.

## RMQ1 integration

This repository contains KVMD application code and nginx templates, not the full
RMQ1 firmware image build tree. The changes must be integrated into the RMQ1
firmware/package build before they can be installed on the device.
