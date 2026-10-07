#!/usr/bin/env python3
"""Loopback VLESS regression: vanilla client, fork server, local TLS 1.3 echo.

Run after building the fork (no network access or third-party Python modules):
  python3 testing/scenarios/vision_tracking.py --server /path/to/fork/xray \
      --client /path/to/vanilla/xray --output /tmp/vision-tracking
Use --expect-broken for the pre-fix fork, or --vanilla-server for a baseline.
Logs and a JSON report are retained; temporary keys, sockets and processes are removed.
"""

import argparse
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time


IDENTITIES = [{"inbound_tag": "vision-test", "user": f"vision-{i}@test.invalid"} for i in range(2)]
UUIDS = ["11111111-2222-4333-8444-555555555555", "22222222-3333-4444-8555-666666666666"]
PAYLOAD = bytes(range(256)) * 256


def receive(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data.extend(chunk)
    return bytes(data)


def wait_for(check, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("condition did not become true")


def unused_port():
    with socket.socket() as conn:
        conn.bind(("127.0.0.1", 0))
        return conn.getsockname()[1]


class UnixHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host)


class TLSEcho(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(10)
            with self.server.tls.wrap_socket(self.request, server_side=True) as conn:
                while data := conn.recv(65536):
                    conn.sendall(data)
        except (OSError, TimeoutError):
            pass  # REALITY target probes and intentional blocks close mid-handshake.


class Fixture:
    def __init__(self, args, root, echo_port, certificate, private_key, public_key, security, flow):
        self.args = args
        self.echo_port = echo_port
        self.name = security + ("-vision" if flow else "-no-flow")
        self.directory = Path(root) / self.name
        self.directory.mkdir()
        self.socket_path = str(self.directory / "control.sock")
        self.server_port = unused_port()
        self.client_ports = [unused_port(), unused_port()]
        self.stats_port = unused_port()
        self.processes = []
        self.logs = []
        self.server_log = args.output / (self.name + "-server.log")
        server_stream = {"network": "tcp", "security": security}
        client_stream = dict(server_stream)
        if security == "reality":
            server_stream["realitySettings"] = {"dest": f"127.0.0.1:{echo_port}", "serverNames": ["localhost"], "privateKey": private_key, "shortIds": [""]}
            client_stream["realitySettings"] = {"serverName": "localhost", "fingerprint": "chrome", "publicKey": public_key, "shortId": ""}
        else:
            server_stream["tlsSettings"] = {"alpn": ["http/1.1"], "certificates": [{"certificateFile": str(certificate), "keyFile": str(certificate.with_suffix(".key"))}]}
            client_stream["tlsSettings"] = {"serverName": "localhost", "pinnedPeerCertSha256": hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text())).hexdigest(), "fingerprint": "chrome", "alpn": ["http/1.1"]}
        server = {
            "log": {"loglevel": "debug"},
            "api": {"tag": "api", "listen": f"127.0.0.1:{self.stats_port}", "services": ["StatsService"]},
            "stats": {},
            "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}, "system": {"statsInboundUplink": True, "statsInboundDownlink": True, "statsOutboundUplink": True, "statsOutboundDownlink": True}},
            "inbounds": [{"listen": "127.0.0.1", "port": self.server_port, "protocol": "vless", "tag": "vision-test", "settings": {"clients": [{"id": UUIDS[i], "email": identity["user"], "flow": flow} for i, identity in enumerate(IDENTITIES)], "decryption": "none"}, "streamSettings": server_stream}],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        }
        client = {
            "log": {"loglevel": "debug"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "tag": f"socks-{i}"} for i, port in enumerate(self.client_ports)],
            "outbounds": [{"protocol": "vless", "tag": f"user-{i}", "settings": {"vnext": [{"address": "127.0.0.1", "port": self.server_port, "users": [{"id": user_id, "encryption": "none", "flow": flow}]}]}, "streamSettings": client_stream} for i, user_id in enumerate(UUIDS)],
            "routing": {"rules": [{"type": "field", "inboundTag": [f"socks-{i}"], "outboundTag": f"user-{i}"} for i in range(2)]},
        }
        try:
            self.start(args.server, "server", server)
            self.start(args.client, "client", client)
        except BaseException:
            self.close()
            raise

    def start(self, binary, role, config):
        path = self.directory / (role + ".json")
        path.write_text(json.dumps(config))
        log = (self.args.output / (self.name + "-" + role + ".log")).open("w")
        self.logs.append(log)
        env = dict(os.environ)
        env.pop("MMWXC_CORE_CONTROL_SOCKET", None)
        if role == "server" and not self.args.vanilla_server:
            env["MMWXC_CORE_CONTROL_SOCKET"] = self.socket_path
        process = subprocess.Popen([str(binary), "run", "-c", str(path)], stdout=log, stderr=subprocess.STDOUT, env=env)
        self.processes.append(process)
        port = self.server_port if role == "server" else self.client_ports[0]
        def ready():
            if process.poll() is not None:
                raise AssertionError(f"{role} exited with {process.returncode}; see logs")
            try:
                with socket.create_connection(("127.0.0.1", port), 0.1):
                    return True
            except OSError:
                return False
        wait_for(ready)

    def close(self):
        for process in reversed(self.processes):
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in self.logs:
            log.close()

    def control(self, method, path, body=None):
        with contextlib.closing(UnixHTTPConnection(self.socket_path, timeout=3)) as conn:
            conn.request(method, path, body=None if body is None else json.dumps(body), headers={"Host": "localhost", "Content-Type": "application/json"})
            response = conn.getresponse()
            result = json.loads(response.read())
            assert response.status == 200, result
            return result

    def config(self, value):
        self.control("PUT", "/v1/config", value)

    def snapshot(self, user=0):
        snapshot = self.control("GET", "/v1/snapshot")
        assert snapshot["version"] == 7, snapshot
        return next((entry for entry in snapshot["proxy_users"] if entry["identity"] == IDENTITIES[user]), {})

    def connect(self, user=0):
        raw = socket.create_connection(("127.0.0.1", self.client_ports[user]), 3)
        try:
            raw.settimeout(10)
            raw.sendall(b"\x05\x01\x00")
            assert receive(raw, 2) == b"\x05\x00"
            raw.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", self.echo_port))
            reply = receive(raw, 4)
            assert reply[:2] == b"\x05\x00", reply
            assert reply[3] == 1, reply
            receive(raw, 6)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls.check_hostname = False
            tls.verify_mode = ssl.CERT_NONE
            tls.minimum_version = ssl.TLSVersion.TLSv1_3
            tls.maximum_version = ssl.TLSVersion.TLSv1_3
            return tls.wrap_socket(raw, server_hostname="localhost")
        except BaseException:
            raw.close()
            raise

    def echo(self, conn, repetitions=1):
        for _ in range(repetitions):
            conn.sendall(PAYLOAD)
            assert receive(conn, len(PAYLOAD)) == PAYLOAD

    def rejected(self):
        try:
            with self.connect() as conn:
                self.echo(conn)
        except TimeoutError:
            raise
        except (OSError, EOFError):
            return
        raise AssertionError("new connection unexpectedly succeeded")

    def stats(self):
        result = subprocess.run([str(self.args.client), "api", "statsquery", f"--server=127.0.0.1:{self.stats_port}"], capture_output=True, text=True, timeout=5, check=True)
        return {item["name"]: int(item.get("value", 0)) for item in json.loads(result.stdout).get("stat", [])}


def run_case(fixture, flow):
    result = {"case": fixture.name}
    if fixture.args.expect_broken and flow:
        fixture.rejected()
        wait_for(lambda: "XTLS only supports TLS and REALITY directly for now." in fixture.server_log.read_text())
        return dict(result, expected_failure="XTLS only supports TLS and REALITY directly for now.")
    with fixture.connect() as conn:
        fixture.echo(conn, 32)
        result["echo_bytes_each_direction"] = 32 * len(PAYLOAD)
        if fixture.args.vanilla_server:
            return dict(result, passed=True)
        active = fixture.snapshot()
        assert active["inbound_active"] == 1 and active["outbound_active"] == 1, active
        assert active["attributed"] and active["inbound_port"] == fixture.server_port, active
        result["active"] = active
        if flow:
            wait_for(lambda: "XtlsFilterTls found tls 1.3!" in fixture.server_log.read_text())
            wait_for(lambda: "command 2" in fixture.server_log.read_text())
            result["tls13_direct_copy"] = True
        live_stats = fixture.stats()
        for direction in ("uplink", "downlink"):
            assert live_stats.get(f"user>>>{IDENTITIES[0]['user']}>>>traffic>>>{direction}", 0) >= len(PAYLOAD), live_stats
        result["live_stats"] = live_stats
    wait_for(lambda: fixture.snapshot().get("inbound_active") == 0)
    wait_for(lambda: fixture.snapshot().get("outbound_active") == 0)
    result["released"] = fixture.snapshot()
    stats = fixture.stats()
    for prefix in (f"user>>>{IDENTITIES[0]['user']}", "inbound>>>vision-test", "outbound>>>direct"):
        for direction in ("uplink", "downlink"):
            value = stats.get(f"{prefix}>>>traffic>>>{direction}", 0)
            assert result["echo_bytes_each_direction"] <= value < result["echo_bytes_each_direction"] * 1.1, stats
    result["final_stats"] = stats
    if not flow:
        return dict(result, passed=True)

    with fixture.connect() as old, fixture.connect(1) as unaffected:
        fixture.echo(old)
        fixture.echo(unaffected)
        fixture.config({"blocked_identities": [IDENTITIES[0]]})
        wait_for(lambda: fixture.snapshot().get("inbound_active") == 0)
        old.settimeout(2)
        try:
            assert old.recv(1) == b"", "blocked tunnel still received data"
        except (ConnectionError, ssl.SSLError):
            pass
        fixture.rejected()
        blocked = fixture.snapshot()
        assert blocked["blocked"] and blocked["rejected_blocked"] > 0, blocked
        fixture.echo(unaffected)
        result["blocked"] = blocked
    fixture.config({"blocked_identities": []})
    with fixture.connect() as conn:
        fixture.echo(conn)
        assert not fixture.snapshot()["blocked"]
    wait_for(lambda: fixture.snapshot().get("inbound_active") == 0)
    wait_for(lambda: fixture.snapshot(1).get("inbound_active") == 0)

    for config, rejected_field in [
        ({"management_mappings": [{"identity": IDENTITIES[0], "group": "vision-user"}], "management_limits": [{"group": "vision-user", "max_inbound_connections": 1}]}, "rejected_user_inbound_limit"),
        ({"port_limits": [{"inbound_tag": "vision-test", "max_inbound_connections": 1}]}, "rejected_port_inbound_limit"),
    ]:
        fixture.config(config)
        with fixture.connect() as conn:
            fixture.echo(conn)
            fixture.rejected()
            assert fixture.snapshot()[rejected_field] > 0, fixture.snapshot()
            fixture.echo(conn)
        wait_for(lambda: fixture.snapshot().get("inbound_active") == 0)
        wait_for(lambda: fixture.snapshot().get("outbound_active") == 0)
    fixture.config({})
    return dict(result, passed=True, block_cut_old_reject_new_unblock=True, other_user_unaffected=True, user_and_port_limits=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-broken", action="store_true")
    parser.add_argument("--vanilla-server", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"server": subprocess.check_output([str(args.server), "version"], text=True).splitlines()[0], "client": subprocess.check_output([str(args.client), "version"], text=True).splitlines()[0], "cases": []}
    with tempfile.TemporaryDirectory(prefix="vision-regression-") as root:
        certificate = Path(root) / "localhost.crt"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", str(certificate.with_suffix(".key")), "-out", str(certificate)], check=True, capture_output=True)
        keys = subprocess.check_output([str(args.client), "x25519"], text=True).splitlines()
        private_key = keys[0].split(": ", 1)[1]
        public_key = keys[1].split(": ", 1)[1]
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.maximum_version = ssl.TLSVersion.TLSv1_3
        tls.set_ecdh_curve("X25519")
        tls.load_cert_chain(certificate, certificate.with_suffix(".key"))
        tls.set_alpn_protocols(["h2", "http/1.1"])
        with TLSEcho(("127.0.0.1", 0), EchoHandler) as echo:
            echo.tls = tls
            thread = threading.Thread(target=echo.serve_forever, daemon=True)
            thread.start()
            try:
                for security in ("reality", "tls"):
                    for flow in ("xtls-rprx-vision", ""):
                        fixture = None
                        try:
                            fixture = Fixture(args, root, echo.server_address[1], certificate, private_key, public_key, security, flow)
                            result = run_case(fixture, flow)
                            report["cases"].append(result)
                            print(json.dumps({"case": result["case"], "passed": result.get("passed", False), "expected_failure": result.get("expected_failure")}))
                        finally:
                            if fixture:
                                fixture.close()
                            (args.output / "report.json").write_text(json.dumps(report, indent=2))
            finally:
                echo.shutdown()
                thread.join()


if __name__ == "__main__":
    main()
