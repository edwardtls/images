# MCP honeypot

This image implements a deliberately inert, remote MCP decoy. It supports the
modern `2026-07-28` discovery flow and the earlier Streamable HTTP handshake so
both new and established MCP clients can interact with it.

The server advertises believable operations tools and emits one bounded JSON
event per request to stdout. It never executes a tool, opens a subprocess,
reads Kubernetes credentials, follows a submitted URL, or initiates a network
connection. This is an intentional credential-capture decoy: submitted
parameters, Authorization headers and cookies are retained verbatim within
the documented size limits.

In Kubernetes the pod has no service-account token, runs as UID 65532 with a
read-only root filesystem, drops every capability, and is covered by a
default-deny egress policy. OTEL forwards its stdout events to Loki.
The process serves TLS directly, so the Traefik-to-pod hop is encrypted too.

What can be observed:

- MCP client identity and protocol version;
- source address, user agent and request timing;
- list/read behavior;
- tool names and complete bounded arguments;
- submitted Authorization and Cookie headers;
- submitted objectives, prompts, commands and retry behavior.

The server cannot observe hidden model reasoning or conversation text that an
MCP client does not transmit.
