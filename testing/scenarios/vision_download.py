#!/usr/bin/env python3
"""Loopback REALITY/Vision HTTPS download with fragmented TLS records.

Uses the production stats, sniffing and routing shape with unlimited identities.
All services bind 127.0.0.1. Requires curl, openssl, Linux /proc and a vanilla client.
  python3 testing/scenarios/vision_download.py --server /path/to/fork/xray \
      --client /path/to/vanilla/xray --output /tmp/vision-download
Use --expect-userspace for 9f7dc23/f44bfba, or --chunk 0 for unfragmented TLS.
Temporary credentials and processes are removed; logs and metrics are retained.
"""

import argparse
import contextlib
import datetime
import json
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time

import vision_tracking as vision


PAYLOAD = bytes(range(256)) * 256


class HTTPSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(120)
            with self.server.tls.wrap_socket(self.request, server_side=True) as conn:
                request = b""
                while b"\r\n\r\n" not in request:
                    data = conn.recv(4096)
                    if not data:
                        return
                    request += data
                header = f"HTTP/1.1 200 OK\r\nContent-Length: {self.server.size}\r\nConnection: close\r\n\r\n".encode()
                for pos in range(0, self.server.size, len(PAYLOAD)):
                    conn.sendall(header + PAYLOAD[:min(len(PAYLOAD), self.server.size - pos)])
                    header = b""
        except OSError:
            pass  # REALITY probes close without an HTTP request.


class FragmentHandler(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.create_connection(("127.0.0.1", self.server.target), 5) as upstream:
            upstream.settimeout(120)
            self.request.settimeout(120)

            def upload():
                try:
                    while data := self.request.recv(65536):
                        upstream.sendall(data)
                    upstream.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            thread = threading.Thread(target=upload, daemon=True)
            thread.start()
            try:
                while data := upstream.recv(self.server.chunk or 65536):
                    self.request.sendall(data)
                    time.sleep(0.001)
                self.request.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            finally:
                with contextlib.suppress(OSError):
                    self.request.shutdown(socket.SHUT_RD)
                thread.join(timeout=2)


class Fixture(vision.Fixture):
    def start(self, binary, role, config):
        if role == "server":
            config["inbounds"][0]["sniffing"] = {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True}
            config["routing"] = {"domainStrategy": "IPIfNonMatch", "rules": [{"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"}]}
            config["outbounds"].append({"protocol": "blackhole", "tag": "block"})
            config["policy"]["levels"]["0"].update(connIdle=300, downlinkOnly=2, handshake=5, uplinkOnly=2)
        super().start(binary, role, config)


def io_stats(pid):
    return {key: int(value) for key, value in (line.split(":") for line in Path(f"/proc/{pid}/io").read_text().splitlines())}


def download(args, fixture, certificate, target_port):
    before = io_stats(fixture.processes[0].pid)
    cmd = ["curl", "--noproxy", "", "--proxy", f"socks5://127.0.0.1:{fixture.client_ports[0]}",
           "--resolve", f"localhost:{target_port}:127.0.0.1", "--cacert", str(certificate),
           "--connect-timeout", "5", "--max-time", "120", "--silent", "--show-error", "--fail",
           "--http1.1", "--tlsv1.3", "--tls-max", "1.3", "--output", "/dev/null", "--write-out", "%{json}",
           f"https://localhost:{target_port}/download"]
    if args.limit_rate:
        cmd.extend(["--limit-rate", args.limit_rate])
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=130)
    after = io_stats(fixture.processes[0].pid)
    curl = json.loads(proc.stdout or "{}")
    result = {"curl_exit": proc.returncode, "curl_stderr": proc.stderr,
              "curl": {key: curl.get(key) for key in ["http_code", "size_download", "time_total", "ssl_verify_result"]},
              "before": before, "after": after, "delta": {key: after[key] - before[key] for key in before}}
    result["ratios"] = {key: result["delta"][key] / args.size for key in ["rchar", "wchar"]}
    vision.wait_for(lambda: fixture.snapshot().get("inbound_active") == 0)
    vision.wait_for(lambda: fixture.snapshot().get("outbound_active") == 0)
    result["stats"] = fixture.stats()
    result["snapshot"] = fixture.snapshot()
    log = fixture.server_log.read_text()
    result["splice_log"] = "CopyRawConn splice" in log
    result["tls13_log"] = "XtlsFilterTls found tls 1.3!" in log
    result["downlink_direct_log"] = any("XtlsPadding " in line and line.endswith(" 2") for line in log.splitlines())
    result["threshold"] = 0.1
    counters = [result["stats"].get(prefix + ">>>traffic>>>downlink", 0)
                for prefix in [f"user>>>{vision.IDENTITIES[0]['user']}", "inbound>>>vision-test", "outbound>>>direct"]]
    result["accounting_passed"] = all(args.size <= value < args.size * 1.3 for value in counters)
    transport_ok = proc.returncode == 0 and curl.get("http_code") == 200 and curl.get("size_download") == args.size and curl.get("ssl_verify_result") == 0
    if args.expect_userspace:
        path_ok = not result["splice_log"] and all(value > 0.9 for value in result["ratios"].values())
    else:
        path_ok = result["splice_log"] and result["downlink_direct_log"] and all(0 <= value < result["threshold"] for value in result["ratios"].values())
    result["passed"] = transport_ok and result["tls13_log"] and path_ok and result["accounting_passed"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--size", type=int, default=33554432)
    parser.add_argument("--limit-rate", default="1M")
    parser.add_argument("--chunk", type=int, default=1200)
    parser.add_argument("--expect-userspace", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    args.vanilla_server = False
    result = {"started_at_taiwan": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
              "server": subprocess.check_output([str(args.server), "version"], text=True).splitlines()[0],
              "client": subprocess.check_output([str(args.client), "version"], text=True).splitlines()[0],
              "size": args.size, "chunk": args.chunk, "limit_rate": args.limit_rate, "expect_userspace": args.expect_userspace}
    with tempfile.TemporaryDirectory(prefix="vision-download-") as root:
        certificate = Path(root) / "localhost.crt"
        key = certificate.with_suffix(".key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", str(key), "-out", str(certificate)], check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = tls.maximum_version = ssl.TLSVersion.TLSv1_3
        tls.set_ecdh_curve("X25519")
        tls.load_cert_chain(certificate, key)
        tls.set_alpn_protocols(["http/1.1"])
        # A separate small ticket record can accidentally hide the boundary bug.
        tls.num_tickets = 0
        keys = subprocess.check_output([str(args.client), "x25519"], text=True).splitlines()
        with vision.TLSEcho(("127.0.0.1", 0), HTTPSHandler) as target, vision.TLSEcho(("127.0.0.1", 0), FragmentHandler) as relay:
            target.tls, target.size = tls, args.size
            relay.target, relay.chunk = target.server_address[1], args.chunk
            threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in [target, relay]]
            for thread in threads:
                thread.start()
            fixture = None
            try:
                fixture = Fixture(args, root, target.server_address[1], certificate, keys[0].split(": ", 1)[1], keys[1].split(": ", 1)[1], "reality", "xtls-rprx-vision")
                fixture.config({"online_ip_grace_period_seconds": 30, "blocked_identities": [],
                                "management_mappings": [{"identity": identity, "group": f"user-{i}"} for i, identity in enumerate(vision.IDENTITIES)]})
                result.update(download(args, fixture, certificate, relay.server_address[1] if args.chunk else target.server_address[1]))
            finally:
                if fixture:
                    fixture.close()
                for server in [target, relay]:
                    server.shutdown()
                for thread in threads:
                    thread.join()
                result["cleaned"] = True
                (args.output / "report.json").write_text(json.dumps(result, indent=2))
    print(json.dumps({key: result.get(key) for key in ["server", "curl_exit", "ratios", "splice_log", "downlink_direct_log", "accounting_passed", "passed", "cleaned"]}))
    assert result["passed"], "see report.json and server log"


if __name__ == "__main__":
    main()
