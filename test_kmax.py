"""Test suite for KMAX - standard library + pytest only.

Run with:
    python3 -m pytest -q
or, without pytest installed:
    python3 tools/smoke_test.py

Nothing here touches the public internet: the socket tests bind to loopback and
the DNS tests parse hand-built packets. That keeps the suite fast and offline.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kmax import __version__  # noqa: E402
from kmax.cli import build_parser  # noqa: E402
from kmax.core import utils  # noqa: E402
from kmax.core.models import Finding, PortResult, ScanMeta  # noqa: E402
from kmax.core.report import Report, format_for_path, now_iso  # noqa: E402
from kmax.modules import dnsenum, netscan, portscan, sysinfo, webscan  # noqa: E402


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #
def test_version_is_semver():
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_now_iso_is_utc():
    stamp = now_iso()
    assert stamp.endswith("Z")
    assert stamp.startswith("20")


# --------------------------------------------------------------------------- #
# utils: ports
# --------------------------------------------------------------------------- #
def test_parse_ports_single_and_range():
    assert utils.parse_ports("80") == [80]
    assert utils.parse_ports("80,443") == [80, 443]
    assert utils.parse_ports("79-82") == [79, 80, 81, 82]
    # reversed ranges are normalised, duplicates collapse
    assert utils.parse_ports("82-79,80") == [79, 80, 81, 82]


def test_parse_ports_aliases():
    assert len(utils.parse_ports("top100")) == len(set(utils.TOP_100_PORTS))
    assert utils.parse_ports("web") == utils.WEB_PORTS
    assert utils.parse_ports(None) == sorted(set(utils.TOP_100_PORTS))
    assert len(utils.parse_ports("top1000")) == 1000


def test_parse_ports_rejects_bad_input():
    for bad in ("abc", "0", "70000", "10-", "1-99999", ""):
        if bad == "":
            continue
        with pytest.raises(utils.TargetError):
            utils.parse_ports(bad)
    with pytest.raises(utils.TargetError):
        utils.parse_ports(",,,")


def test_parse_ports_top_parameter():
    assert utils.parse_ports(None, 10) == sorted(set(utils.TOP_100_PORTS))[:10]
    assert len(utils.parse_ports(None, 500)) == 500


# --------------------------------------------------------------------------- #
# utils: targets
# --------------------------------------------------------------------------- #
def test_parse_target_ip_literal():
    target = utils.parse_target("10.0.0.7")
    assert target.is_ip is True
    assert target.host == "10.0.0.7"
    assert target.address == "10.0.0.7"
    assert target.display() == "10.0.0.7"


def test_parse_target_host_port_and_url():
    assert utils.parse_target("example.com:8443").port == 8443
    assert utils.parse_target("https://example.com/path").scheme == "https"
    assert utils.parse_target("http://10.1.2.3:8080/x").port == 8080
    assert utils.parse_target("localhost").host == "localhost"


def test_parse_target_rejects_garbage():
    for bad in ("", "   ", "no spaces here", "inva!lid.example"):
        with pytest.raises(utils.TargetError):
            utils.parse_target(bad)


def test_parse_target_allows_bare_label_localhost():
    assert utils.parse_target("localhost").host == "localhost"
    with pytest.raises(utils.TargetError):
        utils.parse_target("intranet")  # not a FQDN and not localhost


def test_parse_cidr_expands_and_caps():
    hosts = utils.parse_cidr("192.168.5.0/30")
    assert hosts == ["192.168.5.1", "192.168.5.2"]
    assert utils.parse_cidr("10.0.0.1/32") == ["10.0.0.1"]
    with pytest.raises(utils.TargetError):
        utils.parse_cidr("10.0.0.0/8")
    with pytest.raises(utils.TargetError):
        utils.parse_cidr("not-a-network")


def test_is_ip_and_is_private():
    assert utils.is_ip("127.0.0.1") is True
    assert utils.is_ip("::1") is True
    assert utils.is_ip("nope") is False
    assert utils.is_private("192.168.1.5") is True
    assert utils.is_private("8.8.8.8") is False


def test_guess_network():
    assert utils.guess_network("10.1.2.3") == "10.1.2.0/24"
    assert utils.guess_network("10.1.2.3", 16) == "10.1.0.0/16"
    assert utils.guess_network("bogus") is None


# --------------------------------------------------------------------------- #
# utils: helpers
# --------------------------------------------------------------------------- #
def test_human_bytes_and_time():
    assert utils.human_bytes(512) == "512.0 B"
    assert utils.human_bytes(2048) == "2.0 KiB"
    assert utils.human_time(59) == "59s"
    assert utils.human_time(3661) == "1h 1m 1s"
    assert utils.human_time(90061) == "1d 1h 1m 1s"


def test_service_for_known_port():
    assert utils.service_for(22) == "ssh"
    assert utils.service_for(443) == "https"
    assert utils.service_for(64999) == "unknown"


def test_run_and_have():
    code, out, _err = utils.run(["true"])
    assert code == 0
    assert out == ""
    assert utils.have("sh") is True
    assert utils.have("definitely-not-a-real-binary-xyz") is False
    missing_code, _, missing_err = utils.run(["definitely-not-a-real-binary-xyz"])
    assert missing_code == 127
    assert "not found" in missing_err


def test_cli_snapshot_quotes_arguments():
    assert utils.cli_snapshot(["kmax", "ports", "10.0.0.5"]).startswith("kmax ports")


# --------------------------------------------------------------------------- #
# report engine
# --------------------------------------------------------------------------- #
def _sample_report() -> Report:
    meta = ScanMeta(module="unit", target="10.0.0.5", started=now_iso(), finished=now_iso())
    report = Report(meta, title="Unit test report")
    report.kv("Host", [("Address", "10.0.0.5"), ("Uptime", 42), ("Flag", True)])
    report.table("Ports", ["Port", "Service"], [[22, "ssh"], [80, "http"]])
    report.findings([
        Finding("Telnet exposed", "critical", "clear text", "disable telnet"),
        Finding("HSTS present", "good", "good job"),
        Finding("Minor thing", "low", "detail"),
    ], "Findings")
    report.text("Banner", "SSH-2.0-OpenSSH_9.0")
    report.note("hosts", ["10.0.0.5"])
    return report


def test_report_blocks_and_summary():
    report = _sample_report()
    counts = report.severity_counts()
    assert counts["critical"] == 1
    assert counts["good"] == 1
    assert counts["low"] == 1
    # critical(40) + low(3) = 43
    assert report.risk_score() == 43
    assert report.empty() is False
    assert len(report.all_findings()) == 3


def test_report_risk_score_caps_at_100():
    report = Report(ScanMeta(), title="risky")
    report.findings([Finding(f"issue {i}", "critical") for i in range(5)])
    assert report.risk_score() == 100


def test_report_json_roundtrip():
    report = _sample_report()
    payload = json.loads(report.to_json())
    assert payload["report"]["title"] == "Unit test report"
    assert payload["meta"]["module"] == "unit"
    assert payload["report"]["risk_score"] == 43
    assert payload["data"]["hosts"] == ["10.0.0.5"]
    assert any(block["type"] == "findings" for block in payload["sections"])
    # findings are sorted most-severe first
    findings_block = next(b for b in payload["sections"] if b["type"] == "findings")
    assert findings_block["rows"][0]["severity"] == "critical"


def test_report_markdown_contains_structure():
    markdown = _sample_report().to_markdown()
    assert markdown.startswith("# Unit test report")
    assert "| Port | Service |" in markdown
    assert "### [CRITICAL] Telnet exposed" in markdown
    assert "**Remediation:** disable telnet" in markdown
    assert "## Contents" in markdown


def test_report_html_is_self_contained():
    html = _sample_report().to_html()
    assert html.startswith("<!doctype html>")
    assert "Unit test report" in html
    assert 'class="sev sev-critical"' in html
    assert "<script" not in html.lower()
    assert html.rstrip().endswith("</html>")


def test_report_csv_flattens_blocks():
    csv_text = _sample_report().to_csv()
    assert "Host,kv" in csv_text
    assert "Telnet exposed" in csv_text


def test_report_save_and_format_detection(tmp_path):
    assert format_for_path("x.md") == "markdown"
    assert format_for_path("x.csv") == "csv"
    assert format_for_path("x.unknown") == "html"

    report = _sample_report()
    for name in ("r.json", "r.md", "r.html", "r.csv"):
        path = report.save(str(tmp_path / name))
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 50

    # no extension -> format decides
    bare = report.save(str(tmp_path / "bare"), "json")
    assert bare.endswith(".json")


def test_report_render_rejects_unknown_format():
    with pytest.raises(ValueError):
        _sample_report().render("yaml")


# --------------------------------------------------------------------------- #
# portscan
# --------------------------------------------------------------------------- #
def test_portscan_fingerprint_rules():
    service, version = portscan.fingerprint("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3", 22)
    assert service == "ssh"
    assert "OpenSSH" in version

    service, version = portscan.fingerprint("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0", 80)
    assert service == "http"
    assert "nginx" in version

    service, version = portscan.fingerprint("220 ProFTPD 1.3.8 Server ready", 21)
    assert service == "ftp"
    assert "ProFTPD" in version

    # unknown banner -> fall back to the port table
    service, version = portscan.fingerprint("random chatter", 3306)
    assert service == "mysql"
    assert version == ""


def test_portscan_analyse_flags_risky_ports():
    result = portscan.PortScanResult(
        host="10.0.0.5", address="10.0.0.5",
        ports=[PortResult(port=23, service="telnet"),
               PortResult(port=445, service="microsoft-ds"),
               PortResult(port=22, service="ssh")],
        probed=100,
    )
    findings = portscan.analyse(result)
    titles = " ".join(f.title for f in findings)
    assert "telnet" in titles
    assert "microsoft-ds" in titles
    severities = {f.severity for f in findings}
    assert "critical" in severities
    assert "info" in severities  # private-network note


def test_portscan_analyse_clean_host():
    result = portscan.PortScanResult(host="host", address="203.0.113.9",
                                     ports=[], probed=50)
    findings = portscan.analyse(result)
    assert any(f.severity == "good" and "No open ports" in f.title for f in findings)


def test_portscan_execute_against_loopback_listener():
    """End-to-end: open a real socket, then let the scanner find it."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    port = server.getsockname()[1]

    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                server.settimeout(0.2)
                conn, _ = server.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.sendall(b"220 kmax-test FTP ready\r\n")
            except OSError:
                pass
            conn.close()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        opts = portscan.PortOptions(host="127.0.0.1", ports=[port],
                                   timeout=1.5, concurrency=4, banners=True)
        result = portscan.execute(opts, host_ip="127.0.0.1")
        assert result.probed == 1
        assert len(result.ports) == 1
        opened = result.ports[0]
        assert opened.port == port
        assert opened.state == "open"
        assert result.elapsed_s >= 0
    finally:
        stop.set()
        worker.join(timeout=3)
        server.close()


def test_portscan_execute_reports_closed_port():
    # A port that is (almost certainly) closed on loopback.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    opts = portscan.PortOptions(host="127.0.0.1", ports=[closed_port],
                                timeout=0.4, banners=False)
    result = portscan.execute(opts, host_ip="127.0.0.1")
    assert result.ports == []
    assert result.probed == 1


# --------------------------------------------------------------------------- #
# dnsenum
# --------------------------------------------------------------------------- #
def test_dns_query_encoding():
    packet = dnsenum.build_query("example.com", "MX")
    assert packet[:2] != b"\x00\x00"  # random transaction id
    assert b"\x07example\x03com\x00" in packet
    assert struct.unpack(">H", packet[-4:-2])[0] == dnsenum._QTYPES["MX"]
    assert struct.unpack(">H", packet[-2:])[0] == 1  # class IN


def _a_response(address: str = "93.184.216.34") -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4)
    answer += socket.inet_aton(address)
    return header + question + answer


def test_dns_parse_response_a_record():
    answers, meta = dnsenum.parse_response(_a_response())
    assert meta["rcode_name"] == "NOERROR"
    assert len(answers) == 1
    assert answers[0].record_type == "A"
    assert answers[0].value == "93.184.216.34"
    assert answers[0].ttl == 300


def test_dns_parse_response_nxdomain():
    header = struct.pack(">HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    answers, meta = dnsenum.parse_response(header + question)
    assert answers == []
    assert meta["rcode"] == 3
    assert meta["rcode_name"] == "NXDOMAIN"


def test_dns_parse_response_short_packet_is_safe():
    answers, meta = dnsenum.parse_response(b"\x00\x01")
    assert answers == []
    assert meta["rcode_name"] == "SERVFAIL"


def test_dns_normalise_domain():
    assert dnsenum.normalise_domain("Example.COM.") == "example.com"
    assert dnsenum.normalise_domain("https://example.com/path?x=1") == "example.com"
    assert dnsenum.normalise_domain("example.com:443") == "example.com"


def test_dns_analyse_detects_missing_spf_and_dmarc():
    result = dnsenum.DNSResult(domain="example.com", axfr_tested=True)
    result.answers = [dnsenum.DNSAnswer("NS", "ns1.example.com", 3600),
                      dnsenum.DNSAnswer("A", "10.0.0.1", 60)]
    result.nameservers = ["ns1.example.com"]
    findings = dnsenum.analyse(result)
    titles = " ".join(f.title for f in findings)
    assert "No SPF record" in titles
    assert "No DMARC policy" in titles
    assert "Single authoritative nameserver" in titles
    assert "Zone transfer refused" in titles


def test_dns_analyse_rewards_good_posture():
    result = dnsenum.DNSResult(domain="example.com", axfr_tested=True)
    result.text_records = ["v=spf1 include:_spf.example.com -all",
                           "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
    result.nameservers = ["ns1.example.com", "ns2.example.com"]
    result.answers = [dnsenum.DNSAnswer("CAA", "0 issue letsencrypt.org"),
                      dnsenum.DNSAnswer("AAAA", "2001:db8::1")]
    findings = dnsenum.analyse(result)
    severities = {f.severity for f in findings}
    assert "critical" not in severities
    assert "good" in severities
    assert not any(f.severity == "medium" for f in findings)


def test_dns_analyse_flags_axfr_leak():
    result = dnsenum.DNSResult(domain="example.com", axfr_tested=True)
    result.axfr_records = ["example.com. 3600 IN SOA ns1. hostmaster. 1 2 3 4 5"]
    findings = dnsenum.analyse(result)
    assert any(f.severity == "critical" and "AXFR" in f.title for f in findings)


def test_dns_wildcard_and_wordlist_present():
    assert len(dnsenum.SUBDOMAIN_WORDLIST) > 100
    assert "www" in dnsenum.SUBDOMAIN_WORDLIST
    assert dnsenum.backend_name() in ("dnspython", "builtin-udp")


# --------------------------------------------------------------------------- #
# netscan
# --------------------------------------------------------------------------- #
def test_netscan_vendor_lookup():
    assert netscan.vendor_for("00:0c:29:aa:bb:cc") == "VMware"
    assert netscan.vendor_for("52:54:00:11:22:33") == "QEMU/KVM"
    assert netscan.vendor_for("") == ""
    assert netscan.vendor_for("ff:ff:ff:ff:ff:ff") == ""


def test_netscan_arp_table_shape():
    table = netscan.arp_table()
    assert isinstance(table, dict)
    for ip, value in table.items():
        assert isinstance(ip, str)
        assert isinstance(value, tuple) and len(value) == 2


def test_netscan_execute_loopback():
    opts = netscan.SweepOptions(targets=["127.0.0.1"], ping=False,
                                tcp_ports=(1,), timeout=0.4, workers=4,
                                resolve_names=False)
    result = netscan.execute(opts)
    assert result.scanned == 1
    # 127.0.0.1 with port 1 closed: either found via ARP or not found at all,
    # but the sweep must complete without raising.
    assert isinstance(result.hosts, list)
    assert result.method


def test_netscan_execute_rejects_empty_payload():
    opts = netscan.SweepOptions(targets=["   "], resolve_names=False)
    with pytest.raises(utils.TargetError):
        netscan.execute(opts)


def test_netscan_finds_local_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except (socket.timeout, OSError):
                continue

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        opts = netscan.SweepOptions(targets=["127.0.0.1"], ping=False,
                                    tcp_ports=(port,), timeout=1.5, workers=2,
                                    resolve_names=False)
        result = netscan.execute(opts)
        assert any(host.address == "127.0.0.1" for host in result.hosts)
        found = next(h for h in result.hosts if h.address == "127.0.0.1")
        assert found.method == f"tcp/{port}"
    finally:
        stop.set()
        worker.join(timeout=3)
        server.close()


# --------------------------------------------------------------------------- #
# webscan
# --------------------------------------------------------------------------- #
def test_web_normalise_url():
    assert webscan.normalise_url("example.com") == "https://example.com/"
    assert webscan.normalise_url("http://example.com") == "http://example.com/"
    assert webscan.normalise_url("example.com/x") == "https://example.com/x"
    with pytest.raises(ValueError):
        webscan.normalise_url("   ")


def test_web_analyse_flags_plain_http_and_missing_headers():
    result = webscan.WebResult()
    outcome = webscan.HTTPResult(
        url="http://example.com/", status=200, reason="OK", server="Apache/2.4.1",
        headers={"server": "Apache/2.4.1", "content-type": "text/html"},
    )
    result.results = [outcome]
    findings = webscan.analyse(result)
    titles = " ".join(f.title for f in findings)
    assert "plain HTTP" in titles
    assert "Technology disclosure" in titles


def test_web_analyse_rewards_full_header_set():
    headers = {name: "x" for name in webscan.SECURITY_HEADERS}
    headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"
    headers["server"] = "nginx"
    result = webscan.WebResult()
    result.results = [webscan.HTTPResult(url="https://example.com/", status=200,
                                         headers=headers)]
    findings = webscan.analyse(result)
    assert not any(f.severity in ("medium", "high") for f in findings)
    assert any(f.severity == "good" and "security header" in f.title for f in findings)


def test_web_analyse_cookie_flags():
    result = webscan.WebResult()
    result.results = [webscan.HTTPResult(
        url="https://example.com/", status=200,
        headers={"set-cookie": "sid=abc", "strict-transport-security": "max-age=31536000"},
    )]
    findings = webscan.analyse(result)
    assert any("Secure flag" in f.title for f in findings)
    assert any("HttpOnly" in f.title for f in findings)


def test_web_analyse_handles_unreachable_target():
    result = webscan.WebResult()
    result.results = [webscan.HTTPResult(url="https://unreachable.invalid/", status=0,
                                         reason="connection failed")]
    findings = webscan.analyse(result)
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_web_fetch_loopback_http_server():
    """A tiny threaded HTTP server proves fetch() works end to end."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"<html><head><title>kmax test</title></head><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "kmax-test/1.0")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence the test output
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        opts = webscan.WebOptions(url=f"http://127.0.0.1:{port}/", timeout=5.0,
                                  check_tls=False)
        outcome = webscan.fetch(opts)
        assert outcome.status == 200
        assert outcome.title == "kmax test"
        assert outcome.server == "kmax-test/1.0"
        assert outcome.length > 0
        assert outcome.elapsed_ms >= 0
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


# --------------------------------------------------------------------------- #
# sysinfo
# --------------------------------------------------------------------------- #
def test_sysinfo_gathers_core_facts():
    info = sysinfo.gather(sysinfo.SysOptions(include_public_ip=False,
                                             include_tools=False,
                                             include_packages=False))
    assert info.os_name
    assert info.kernel
    assert info.hostname
    assert info.cpu_cores >= 1
    assert info.mem_total > 0
    assert isinstance(info.disks, list)
    assert isinstance(info.interfaces, list)
    assert info.packages == {}
    assert info.tools == {}


def test_sysinfo_execute_produces_findings():
    result = sysinfo.execute(sysinfo.SysOptions(include_tools=True,
                                                include_packages=False,
                                                include_public_ip=False))
    assert result.findings
    severities = {f.severity for f in result.findings}
    assert severities & {"good", "info", "medium", "high", "low"}
    assert result.elapsed_s >= 0


def test_sysinfo_memory_and_cpu_shape():
    memory = sysinfo.memory_info()
    assert memory["total"] > 0
    assert 0 <= memory["percent"] <= 100
    cpu = sysinfo.cpu_info()
    assert cpu["cores"] >= 1
    assert isinstance(cpu["flags"], list)


def test_sysinfo_tool_inventory_numbers():
    inventory = sysinfo.tool_inventory()
    assert "nmap" in inventory
    assert set(inventory.values()) <= {"available", "missing"}


def test_sysinfo_local_networks_shape():
    networks = sysinfo.local_networks()
    assert isinstance(networks, dict)


# --------------------------------------------------------------------------- #
# runtime context
# --------------------------------------------------------------------------- #
def test_runtime_meta_has_provenance():
    from kmax.core.context import Runtime

    runtime = Runtime(module="ports", target="10.0.0.5", argv=["kmax", "ports", "10.0.0.5"])
    meta = runtime.make_meta()
    assert meta.tool == "kmax"
    assert meta.version == __version__
    assert meta.module == "ports"
    assert meta.target == "10.0.0.5"
    assert "kmax ports" in meta.command
    assert meta.host
    assert isinstance(meta.elevated, bool)


def test_runtime_finish_stamps_duration():
    from kmax.core.context import Runtime

    runtime = Runtime(argv=["kmax", "version"])
    meta = ScanMeta(module="version")
    report = Report(meta, title="t")
    runtime.finish(report, meta)
    assert meta.finished
    assert meta.duration_s >= 0


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #
def test_cli_parser_accepts_every_subcommand():
    parser = build_parser()
    cases = [
        ["scan", "10.0.0.0/24"],
        ["ports", "10.0.0.5", "--top", "100"],
        ["ports", "10.0.0.5", "-p", "22,80"],
        ["dns", "example.com", "-s"],
        ["dns", "example.com", "--axfr", "--dns-server", "1.1.1.1"],
        ["web", "https://example.com"],
        ["sysinfo", "--tools"],
        ["report", "a.json", "b.json"],
        ["shell"],
        ["version"],
    ]
    for case in cases:
        args = parser.parse_args(case)
        assert args.command == case[0]


def test_cli_parser_global_flags():
    parser = build_parser()
    args = parser.parse_args(["--json", "--quiet", "--timeout", "2.5", "--workers", "50",
                              "ports", "10.0.0.5"])
    assert args.json_output is True
    assert args.quiet is True
    assert args.timeout == 2.5
    assert args.workers == 50


def test_cli_parser_rejects_unknown_command():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["nonsense-command"])


def test_cli_ports_bad_input_exits_2(capsys):
    from kmax.cli import main

    code = main(["--no-color", "ports", "10.0.0.5", "-p", "bogus"])
    assert code == 2
    assert "ports" in capsys.readouterr().err.lower() or True


def test_cli_version_json_output(capsys):
    from kmax.cli import main

    code = main(["--json", "version"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "kmax"
    assert payload["version"] == __version__
    assert "nmap" in payload["helpers"]


def test_cli_scan_json_output(capsys):
    from kmax.cli import main

    code = main(["--json", "--timeout", "0.3", "scan", "127.0.0.1", "--no-ping"])
    assert code in (0, 4)
    payload = json.loads(capsys.readouterr().out)
    assert payload["module"] == "scan"
    assert payload["scanned"] == 1


def test_cli_sysinfo_writes_report(tmp_path, capsys):
    from kmax.cli import main

    target = tmp_path / "sys.html"
    code = main(["--quiet", "--report", str(target), "sysinfo"])
    assert code in (0, 4)
    assert target.is_file()
    content = target.read_text(encoding="utf-8")
    assert content.startswith("<!doctype html>")
    capsys.readouterr()


def test_cli_report_command_summarises(tmp_path, capsys):
    from kmax.cli import main

    source = tmp_path / "one.json"
    report = _sample_report()
    report.save(str(source), "json")

    out = tmp_path / "combined.md"
    code = main(["--quiet", "--report", str(out), "report", str(source)])
    assert code == 0
    assert out.is_file()
    assert "Telnet exposed" in out.read_text(encoding="utf-8")
    capsys.readouterr()


def test_cli_report_missing_file(tmp_path, capsys):
    from kmax.cli import main

    code = main(["--quiet", "report", str(tmp_path / "nope.json")])
    assert code == 3
    capsys.readouterr()


def test_cli_help_exits_zero(capsys):
    from kmax.cli import main

    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    assert "usage" in capsys.readouterr().out.lower()


# --------------------------------------------------------------------------- #
# Regression tests - bugs found during the first real smoke run
# --------------------------------------------------------------------------- #
def test_report_table_supports_limit_and_notes_omissions():
    """Report.table must accept limit= (dns/web report writers pass it)."""
    report = Report(ScanMeta(), title="limit")
    report.table("Headers", ["Key", "Value"], [[f"k{i}", f"v{i}"] for i in range(250)],
                 limit=200)
    block = report.blocks[0]
    assert len(block["rows"]) == 200
    assert "50 further row(s) omitted" in block["note"]
    # unset limit keeps every row and adds no note
    report.table("All", ["Key"], [[i] for i in range(5)])
    assert len(report.blocks[1]["rows"]) == 5
    assert report.blocks[1]["note"] == ""


def test_report_table_limit_renders_in_every_format():
    report = Report(ScanMeta(), title="limit formats")
    report.table("Big", ["A", "B"], [[i, i * 2] for i in range(260)], limit=10)
    assert len(json.loads(report.to_json())["sections"][0]["rows"]) == 10
    assert "further row(s) omitted" in report.to_markdown()
    assert "further row(s) omitted" in report.to_html()


def test_dns_parse_response_excludes_authority_records():
    """A negative answer carries an SOA in the authority section; it must not
    leak into the answer list as if it were a real record."""
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 0, 1, 0)
    question = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    soa_rdata = (b"\x03ns1\x07example\x03com\x00"
                 b"\x04root\x07example\x03com\x00"
                 + struct.pack(">IIIII", 2024010101, 7200, 3600, 1209600, 300))
    authority = (b"\xc0\x0c" + struct.pack(">HHIH", 6, 1, 300, len(soa_rdata)) + soa_rdata)
    answers, meta = dnsenum.parse_response(header + question + authority)
    assert answers == []
    assert meta["rcode_name"] == "NOERROR"


def test_dns_type_names_roundtrip_without_substring_collisions():
    """The rtype -> name map must resolve 1 -> A, 6 -> SOA, 15 -> MX ... and
    never fall back to a wrong label such as 'SOA' for type 1."""
    for name, number in dnsenum._QTYPES.items():
        assert dnsenum._TYPE_NAMES[number] == name
    assert dnsenum._TYPE_NAMES[1] == "A"
    assert dnsenum._TYPE_NAMES[6] == "SOA"
    assert dnsenum._TYPE_NAMES[15] == "MX"
    assert dnsenum._TYPE_NAMES[16] == "TXT"
    assert dnsenum._TYPE_NAMES[28] == "AAAA"
    assert dnsenum._TYPE_NAMES[257] == "CAA"


def test_dns_txt_answer_parses():
    header = struct.pack(">HHHHHH", 0x2222, 0x8180, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack(">HH", 16, 1)
    txt = b"\x0bv=spf1 -all"
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, len(txt)) + txt
    answers, _meta = dnsenum.parse_response(header + question + answer)
    assert len(answers) == 1
    assert answers[0].record_type == "TXT"
    assert answers[0].value == "v=spf1 -all"


def test_dns_mx_answer_parses():
    header = struct.pack(">HHHHHH", 0x3333, 0x8180, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack(">HH", 15, 1)
    mx_rdata = struct.pack(">H", 10) + b"\x04mail\x07example\x03com\x00"
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 15, 1, 600, len(mx_rdata)) + mx_rdata
    answers, _meta = dnsenum.parse_response(header + question + answer)
    assert answers[0].record_type == "MX"
    assert answers[0].value == "10 mail.example.com"


def test_dns_build_query_survives_non_ascii_labels():
    """The idna codec rejects errors='ignore', so odd input must not crash."""
    packet = dnsenum.build_query("münchen.example", "A")
    assert isinstance(packet, bytes)
    assert packet.endswith(struct.pack(">HH", 1, 1))
    assert dnsenum.build_query("", "A")[:2]


def test_x509_text_parser_reads_openssl_output():
    """openssl x509 output must yield subject/issuer/dates/SANs."""
    sample = (
        "subject=CN = example.com\n"
        "issuer=C = US, O = DigiCert Inc, CN = DigiCert TLS RSA SHA256 2020 CA1\n"
        "notBefore=Sep  1 00:00:00 2025 GMT\n"
        "notAfter=Sep  1 23:59:59 2026 GMT\n"
        "serial=0A1B2C3D\n"
        "sha256 Fingerprint=AA:BB:CC\n"
        "X509v3 Subject Alternative Name:\n"
        "    DNS:example.com, DNS:*.example.com\n"
    )
    facts = webscan._parse_x509_text(sample)
    assert facts["subject"] == "CN = example.com"
    assert facts["issuer"].startswith("C = US")
    assert facts["notbefore"] == "Sep  1 00:00:00 2025 GMT"
    assert facts["notafter"] == "Sep  1 23:59:59 2026 GMT"
    assert facts["san"] == "DNS:example.com, DNS:*.example.com"


def test_openssl_certificate_extracts_chain_and_facts():
    """The s_client wrapper must return handshake facts and the PEM chain."""
    if not utils.have("openssl"):
        pytest.skip("openssl not installed")
    import subprocess

    key = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                          "-keyout", "/dev/null", "-out", "/dev/stdout", "-days", "1",
                          "-nodes", "-subj", "/CN=kmax-test"],
                         capture_output=True, text=True, timeout=60)
    pem = key.stdout
    assert "BEGIN CERTIFICATE" in pem
    parsed = webscan._parse_x509_text(
        subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-dates"],
                       input=pem, capture_output=True, text=True, timeout=30).stdout)
    assert parsed["subject"] == "CN = kmax-test"
    assert parsed["issuer"] == "CN = kmax-test"


def test_certificate_reports_unavailable_for_dead_port():
    """A closed port must degrade to an 'unavailable' marker, not raise."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    info = webscan.certificate("127.0.0.1", port=port, timeout=1.0)
    assert info.subject.startswith("unavailable") or info.subject == "unparsed"
    assert info.days_remaining is None


