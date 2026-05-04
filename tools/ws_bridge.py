#!/usr/bin/env python3
"""
WebSocket <-> TCP bridge for connecting the Reticulum web client to a
local or remote rnsd.

Browsers cannot open raw TCP sockets, so the web client's "TCP"
option actually speaks WebSocket to this bridge, and the bridge
forwards raw bytes to an rnsd that is listening on its standard
TCPServerInterface. HDLC framing is preserved end to end — the
bridge never parses or reassembles frames, it just copies bytes in
both directions. A partial HDLC frame arriving in one WebSocket
message and finishing in the next is fine because the web client's
HdlcParser is a streaming parser.

Requirements
------------
  pip install websockets

Usage
-----
  # 1. Make sure rnsd is running with a TCP server interface, for
  #    example in ~/.reticulum/config:
  #
  #        [[RNS TCP Server Interface]]
  #            type = TCPServerInterface
  #            interface_enabled = True
  #            listen_ip = 0.0.0.0
  #            listen_port = 4242
  #
  # 2. Start the bridge. Defaults listen on ws://localhost:7878 and
  #    forward to tcp://localhost:4242:
  #
  #        python tools/ws_bridge.py
  #
  # 3. In the web client, click "Connect (WebSocket)" with
  #    ws://localhost:7878 in the URL field.
  #
  # Override host/port via CLI args:
  #
  #     python tools/ws_bridge.py --ws-port 7878 --rnsd-host 10.0.0.5 --rnsd-port 4242
  #
  # Note: this bridge IGNORES any ?host=X&port=Y query parameters in
  # the WebSocket URL — it always forwards to the --rnsd-host/--rnsd-port
  # set at startup. The Go bridge in tools/ws_bridge.go uses those query
  # parameters to take the rnsd target per-connection. The webapp sends
  # the query params either way, so the same UI works against either
  # bridge.
"""
import argparse
import asyncio
import sys

try:
    import websockets
except ImportError:
    sys.stderr.write(
        "ERROR: the 'websockets' package is required.\n"
        "Install with: pip install websockets\n"
    )
    sys.exit(1)


async def bridge_client(ws, rnsd_host, rnsd_port):
    """Handle one WebSocket client. Opens a fresh TCP connection to
    rnsd for each WS client and shuttles bytes in both directions."""
    peer = ws.remote_address if hasattr(ws, "remote_address") else "?"
    print(f"[ws_bridge] client connected: {peer}", flush=True)
    try:
        reader, writer = await asyncio.open_connection(rnsd_host, rnsd_port)
    except Exception as e:
        print(f"[ws_bridge] cannot reach rnsd at {rnsd_host}:{rnsd_port}: {e}", flush=True)
        await ws.close(code=1011, reason="rnsd unreachable")
        return

    print(f"[ws_bridge] bridged to rnsd tcp://{rnsd_host}:{rnsd_port}", flush=True)

    async def ws_to_tcp():
        try:
            async for msg in ws:
                if isinstance(msg, (bytes, bytearray)):
                    writer.write(bytes(msg))
                    await writer.drain()
                else:
                    # Web client always sends binary; if a text
                    # message arrives it's a client bug, just drop.
                    print(f"[ws_bridge] ignoring non-binary WS message ({len(msg)} chars)", flush=True)
        except websockets.ConnectionClosed:
            pass
        except Exception as e:
            print(f"[ws_bridge] ws->tcp error: {e}", flush=True)
        finally:
            try: writer.close()
            except Exception: pass

    async def tcp_to_ws():
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    return
                await ws.send(data)
        except websockets.ConnectionClosed:
            pass
        except Exception as e:
            print(f"[ws_bridge] tcp->ws error: {e}", flush=True)

    try:
        await asyncio.gather(ws_to_tcp(), tcp_to_ws())
    finally:
        try: writer.close()
        except Exception: pass
        print(f"[ws_bridge] client disconnected: {peer}", flush=True)


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ws-host", default="localhost", help="WebSocket bind host (default: localhost)")
    ap.add_argument("--ws-port", type=int, default=7878, help="WebSocket bind port (default: 7878)")
    ap.add_argument("--rnsd-host", default="localhost", help="rnsd TCP host (default: localhost)")
    ap.add_argument("--rnsd-port", type=int, default=4242, help="rnsd TCP port (default: 4242)")
    args = ap.parse_args()

    async def handler(ws):
        await bridge_client(ws, args.rnsd_host, args.rnsd_port)

    print(f"[ws_bridge] listening on ws://{args.ws_host}:{args.ws_port}", flush=True)
    print(f"[ws_bridge] forwarding to tcp://{args.rnsd_host}:{args.rnsd_port}", flush=True)
    async with websockets.serve(handler, args.ws_host, args.ws_port):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[ws_bridge] stopped", flush=True)
