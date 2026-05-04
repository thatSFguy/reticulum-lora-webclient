// tools/ws_bridge.go
//
// WebSocket-to-TCP bridge for the Reticulum web client (Go version).
//
// Browsers cannot open raw TCP sockets, so the web client's "TCP"
// option speaks WebSocket to this bridge, which forwards raw bytes
// in both directions to a remote rnsd's TCPServerInterface. HDLC
// framing is preserved end to end — the bridge never parses or
// reassembles frames.
//
// Differences from the Python ws_bridge.py:
//   - The rnsd target (host + port) is supplied PER CONNECTION by the
//     webapp via query parameters: ws://localhost:7878/?host=X&port=Y.
//     The bridge itself takes no rnsd flags — one running bridge can
//     serve any number of webapp instances pointed at any number of
//     different rnsds without restart.
//   - Single self-contained binary, no Python or pip required.
//
// Build:
//   # cross-compile for Windows from any host:
//   GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ws_bridge.exe
//
//   # native build (Linux / macOS / Windows):
//   go build -ldflags="-s -w" -o ws_bridge
//
// The -s -w flags strip the symbol table and DWARF debug info,
// roughly halving the binary. Expect ~3-4 MB stripped on amd64.
//
// Run:
//   ws_bridge.exe                 # listen on localhost:7878
//   ws_bridge.exe -port 9090      # custom port
//   ws_bridge.exe -bind 0.0.0.0   # listen on all interfaces (LAN-visible)

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	// The webapp is served from github.io; the bridge runs on
	// localhost. Cross-origin WS upgrades are blocked by gorilla's
	// default CheckOrigin — open it up. The bridge has no auth and
	// only forwards bytes, so this is fine; if you bind to a LAN
	// interface and care about who can reach it, use a firewall.
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

func handleBridge(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	port := r.URL.Query().Get("port")
	if host == "" || port == "" {
		http.Error(w, "missing required query params: ?host=X&port=Y", http.StatusBadRequest)
		return
	}
	target := net.JoinHostPort(host, port)
	peer := r.RemoteAddr

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[%s] ws upgrade failed: %v", peer, err)
		return
	}
	defer ws.Close()

	log.Printf("[%s] client connected, dialing %s", peer, target)

	tcp, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("[%s] tcp dial %s failed: %v", peer, target, err)
		_ = ws.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "rnsd unreachable"))
		return
	}
	defer tcp.Close()

	log.Printf("[%s] bridged to %s", peer, target)

	// ws -> tcp pump runs in its own goroutine. The tcp -> ws pump
	// runs on this goroutine. Either side closing tears down both:
	// closing tcp causes the read loop in the goroutine to error;
	// closing ws causes the read loop here to error.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			mt, msg, err := ws.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err,
					websocket.CloseNormalClosure,
					websocket.CloseGoingAway,
					websocket.CloseAbnormalClosure) {
					log.Printf("[%s] ws read: %v", peer, err)
				}
				_ = tcp.Close()
				return
			}
			// The webapp always sends binary; drop anything else.
			if mt != websocket.BinaryMessage {
				log.Printf("[%s] ignoring non-binary ws message (type=%d, len=%d)", peer, mt, len(msg))
				continue
			}
			if _, err := tcp.Write(msg); err != nil {
				log.Printf("[%s] tcp write: %v", peer, err)
				return
			}
		}
	}()

	buf := make([]byte, 4096)
	for {
		n, err := tcp.Read(buf)
		if n > 0 {
			if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
				log.Printf("[%s] ws write: %v", peer, werr)
				break
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] tcp read: %v", peer, err)
			}
			break
		}
	}

	_ = ws.Close()
	<-done
	log.Printf("[%s] client disconnected", peer)
}

func main() {
	bind := flag.String("bind", "localhost", "WebSocket bind host (use 0.0.0.0 for LAN-visible)")
	port := flag.Int("port", 7878, "WebSocket bind port")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	http.HandleFunc("/", handleBridge)

	log.Printf("ws_bridge listening on ws://%s (rnsd target supplied per-connection via ?host=X&port=Y)", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
