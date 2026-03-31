"""
APEX Dashboard Server
Real-time fuzzing statistics served as a web dashboard.
Pure Python HTTP + WebSocket server (no external framework needed).
"""

import asyncio
import json
import logging
import time
from pathlib import Path

log = logging.getLogger("apex.dashboard")

# Embedded HTML dashboard (single-file, no external deps)
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APEX Fuzzer Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&family=Orbitron:wght@700;900&display=swap');
  :root {
    --bg: #0a0a0f;
    --panel: #0f0f1a;
    --border: #1a1a2e;
    --accent: #00ff88;
    --accent2: #ff3366;
    --accent3: #3388ff;
    --text: #c8d8e8;
    --dim: #4a5a6a;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    min-height: 100vh;
    padding: 20px;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
    padding-bottom: 16px;
    margin-bottom: 24px;
  }
  h1 {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.4rem;
    color: var(--accent);
    letter-spacing: 4px;
  }
  .status-dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    background: var(--accent);
    animation: pulse 1.5s ease-in-out infinite;
    display: inline-block;
    margin-right: 8px;
  }
  @keyframes pulse {
    0%,100% { opacity: 1; box-shadow: 0 0 0 0 rgba(0,255,136,0.4); }
    50% { opacity: 0.7; box-shadow: 0 0 0 6px rgba(0,255,136,0); }
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 20px;
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent);
  }
  .card.red::before { background: var(--accent2); }
  .card.blue::before { background: var(--accent3); }
  .card-label {
    font-size: 0.65rem;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--dim);
    margin-bottom: 10px;
  }
  .card-value {
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent);
    font-family: 'Orbitron', sans-serif;
  }
  .card.red .card-value { color: var(--accent2); }
  .card.blue .card-value { color: var(--accent3); }
  .card-sub { font-size: 0.7rem; color: var(--dim); margin-top: 6px; }

  .section { margin-bottom: 24px; }
  .section-title {
    font-size: 0.65rem;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--dim);
    margin-bottom: 12px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 6px;
  }

  .crash-list {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 4px;
    max-height: 300px;
    overflow-y: auto;
  }
  .crash-item {
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.78rem;
    transition: background 0.1s;
  }
  .crash-item:hover { background: rgba(255,255,255,0.02); }
  .crash-item:last-child { border-bottom: none; }
  .crash-id { color: var(--accent2); font-weight: 700; }
  .crash-exploitability {
    padding: 2px 8px;
    border-radius: 2px;
    font-size: 0.65rem;
    letter-spacing: 1px;
  }
  .EXPLOITABLE { background: rgba(255,51,102,0.2); color: var(--accent2); }
  .PROBABLY_EXPLOITABLE { background: rgba(255,153,0,0.2); color: #ff9900; }
  .UNKNOWN { background: rgba(100,100,100,0.2); color: #888; }
  .NOT_EXPLOITABLE { background: rgba(0,100,0,0.2); color: #44aa44; }

  .log-pane {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 12px 16px;
    font-size: 0.72rem;
    max-height: 200px;
    overflow-y: auto;
    color: var(--dim);
    line-height: 1.8;
  }
  .log-line.warn { color: #ffaa00; }
  .log-line.error { color: var(--accent2); }
  .log-line.info { color: var(--text); }

  .progress-bar {
    background: var(--border);
    border-radius: 2px;
    height: 6px;
    margin-top: 8px;
    overflow: hidden;
  }
  .progress-fill {
    height: 100%;
    background: var(--accent);
    border-radius: 2px;
    transition: width 0.5s ease;
  }

  .conn-status { font-size: 0.7rem; color: var(--dim); }
  .conn-status.connected { color: var(--accent); }
  .conn-status.disconnected { color: var(--accent2); }
</style>
</head>
<body>
<header>
  <h1>⬡ APEX FUZZER</h1>
  <div>
    <span class="status-dot" id="status-dot"></span>
    <span class="conn-status disconnected" id="conn-status">CONNECTING...</span>
  </div>
</header>

<div class="grid">
  <div class="card">
    <div class="card-label">Total Executions</div>
    <div class="card-value" id="stat-execs">—</div>
    <div class="card-sub" id="stat-eps">— exec/sec</div>
  </div>
  <div class="card blue">
    <div class="card-label">Coverage Paths</div>
    <div class="card-value" id="stat-paths">—</div>
    <div class="progress-bar"><div class="progress-fill" id="cov-fill" style="width:0%"></div></div>
    <div class="card-sub" id="stat-cov">0% map density</div>
  </div>
  <div class="card red">
    <div class="card-label">Unique Crashes</div>
    <div class="card-value" id="stat-crashes">0</div>
    <div class="card-sub" id="stat-crash-last">none yet</div>
  </div>
  <div class="card">
    <div class="card-label">Runtime</div>
    <div class="card-value" id="stat-runtime" style="font-size:1.4rem">00h 00m</div>
    <div class="card-sub" id="stat-corpus">corpus: — seeds</div>
  </div>
</div>

<div class="section">
  <div class="section-title">Crashes</div>
  <div class="crash-list" id="crash-list">
    <div class="crash-item" style="color: var(--dim); justify-content:center">
      No crashes yet — fuzzing in progress
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">Live Log</div>
  <div class="log-pane" id="log-pane">
    <div class="log-line info">APEX dashboard ready. Waiting for fuzzer connection...</div>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
let crashes = [];
let logLines = [];
let ws;

function fmt(n) {
  if (n >= 1e9) return (n/1e9).toFixed(2) + 'B';
  if (n >= 1e6) return (n/1e6).toFixed(2) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
  return String(n);
}

function connect() {
  ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onopen = () => {
    $('conn-status').textContent = 'LIVE';
    $('conn-status').className = 'conn-status connected';
    addLog('Connected to APEX fuzzer', 'info');
  };
  ws.onmessage = e => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'stats') updateStats(msg.data);
    else if (msg.type === 'crash') addCrash(msg.data);
    else if (msg.type === 'log') addLog(msg.data.message, msg.data.level);
  };
  ws.onclose = () => {
    $('conn-status').textContent = 'DISCONNECTED';
    $('conn-status').className = 'conn-status disconnected';
    setTimeout(connect, 2000);
  };
}

function updateStats(s) {
  $('stat-execs').textContent = fmt(s.total_executions || 0);
  $('stat-eps').textContent = fmt(Math.round(s.avg_execs_per_sec || 0)) + ' exec/sec';
  $('stat-paths').textContent = fmt(s.total_paths || 0);
  $('stat-crashes').textContent = s.unique_crashes || 0;
  $('stat-runtime').textContent = s.runtime_human || '00h 00m 00s';
  if (s.coverage_percent !== undefined) {
    $('cov-fill').style.width = Math.min(100, s.coverage_percent) + '%';
    $('stat-cov').textContent = s.coverage_percent.toFixed(1) + '% map density';
  }
}

function addCrash(c) {
  crashes.unshift(c);
  const list = $('crash-list');
  if (crashes.length === 1) list.innerHTML = '';
  const item = document.createElement('div');
  item.className = 'crash-item';
  const expClass = (c.exploitability || 'UNKNOWN').replace(/\s+/g,'_');
  item.innerHTML = `
    <span class="crash-id">${c.crash_id}</span>
    <span>${c.signal_name || '?'}</span>
    <span>sev: ${c.severity_score}/100</span>
    <span class="crash-exploitability ${expClass}">${(c.exploitability||'UNKNOWN').replace(/_/g,' ')}</span>
  `;
  list.insertBefore(item, list.firstChild);
  $('stat-crash-last').textContent = 'last: ' + c.crash_id;
}

function addLog(msg, level = 'info') {
  const pane = $('log-pane');
  const div = document.createElement('div');
  div.className = 'log-line ' + level;
  const ts = new Date().toTimeString().slice(0,8);
  div.textContent = `[${ts}] ${msg}`;
  pane.appendChild(div);
  if (pane.children.length > 100) pane.removeChild(pane.firstChild);
  pane.scrollTop = pane.scrollHeight;
}

connect();
</script>
</body>
</html>
"""


class DashboardServer:
    """
    Minimal async HTTP + WebSocket server for the live dashboard.
    No external dependencies (no aiohttp, no flask).
    """

    def __init__(self, port: int = 8080):
        self.port = port
        self._clients: list = []
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_connection, "0.0.0.0", self.port
        )
        log.info(f"Dashboard: http://localhost:{self.port}")
        async with self._server:
            await self._server.serve_forever()

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter):
        try:
            request_line = await reader.readline()
            request = request_line.decode("utf-8", errors="replace").strip()
            headers = {}
            while True:
                line = await reader.readline()
                line = line.decode("utf-8", errors="replace").strip()
                if not line:
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            if "upgrade" in headers and headers["upgrade"].lower() == "websocket":
                await self._handle_websocket(reader, writer, headers)
            elif "GET / " in request or "GET /index" in request:
                await self._serve_html(writer)
            else:
                writer.write(b"HTTP/1.1 404 Not Found\r\n\r\n")
                await writer.drain()
                writer.close()
        except Exception as e:
            log.debug(f"Dashboard connection error: {e}")

    async def _serve_html(self, writer: asyncio.StreamWriter):
        body = DASHBOARD_HTML.encode("utf-8")
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
        ).encode() + body
        writer.write(response)
        await writer.drain()
        writer.close()

    async def _handle_websocket(self, reader, writer, headers):
        """Minimal WebSocket handshake + framing."""
        import base64, hashlib

        key = headers.get("sec-websocket-key", "")
        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept = base64.b64encode(
            hashlib.sha1((key + magic).encode()).digest()
        ).decode()

        handshake = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        ).encode()
        writer.write(handshake)
        await writer.drain()

        self._clients.append(writer)
        log.info("Dashboard client connected")

        try:
            while True:
                await asyncio.sleep(60)  # Keep alive
        except Exception:
            pass
        finally:
            if writer in self._clients:
                self._clients.remove(writer)
            writer.close()

    async def _broadcast(self, message: dict):
        """Send a JSON message to all connected WebSocket clients."""
        if not self._clients:
            return
        frame = self._ws_encode(json.dumps(message))
        dead = []
        for writer in self._clients:
            try:
                writer.write(frame)
                await writer.drain()
            except Exception:
                dead.append(writer)
        for w in dead:
            self._clients.remove(w)

    @staticmethod
    def _ws_encode(text: str) -> bytes:
        """Encode a text string as a WebSocket frame."""
        data = text.encode("utf-8")
        length = len(data)
        if length < 126:
            header = bytes([0x81, length])
        elif length < 65536:
            header = bytes([0x81, 126]) + length.to_bytes(2, "big")
        else:
            header = bytes([0x81, 127]) + length.to_bytes(8, "big")
        return header + data

    async def push_stats(self, stats):
        """Push stats update to all dashboard clients."""
        await self._broadcast({
            "type": "stats",
            "data": {
                "total_executions": stats.total_executions,
                "avg_execs_per_sec": stats.avg_execs_per_sec,
                "total_paths": stats.total_paths,
                "unique_crashes": stats.unique_crashes,
                "runtime_human": stats.runtime_human,
            }
        })

    async def push_crash(self, crash_id: str, result):
        """Push a new crash notification to dashboard clients."""
        await self._broadcast({
            "type": "crash",
            "data": {
                "crash_id": crash_id,
                "signal": result.signal,
                "signal_name": f"SIG{result.signal}" if result.signal else "UNKNOWN",
                "exploitability": "UNKNOWN",
                "severity_score": 50,
            }
        })

    async def push_log(self, message: str, level: str = "info"):
        await self._broadcast({"type": "log", "data": {"message": message, "level": level}})
