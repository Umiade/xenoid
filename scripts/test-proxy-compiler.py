#!/usr/bin/env python3
"""Focused, runtime-free contracts for proxy compilation and AEAD v1."""
from __future__ import annotations

import base64
import copy
import gzip
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid import proxy_source
from xenoid.daemon_client import wait_for_proxy_check
from xenoid.proxy_controller import ProxyController
from xenoid.proxy_protocol import (
    ProxyProtocolError,
    ReplayWindow,
    derive_key,
    open_request,
    open_response,
    seal_request,
    seal_response,
)
from xenoid.proxy_source import (
    PinnedHTTPSFetcher,
    ProxySourceError,
    compile_source,
)


Case = Callable[[], None]
CASES: Dict[str, Case] = {}


def case(name: str) -> Callable[[Case], Case]:
    def register(function: Case) -> Case:
        if name in CASES:
            raise RuntimeError
        CASES[name] = function
        return function
    return register


def require(value: bool) -> None:
    if not value:
        raise AssertionError


def source_error(code: str, action: Callable[[], Any]) -> None:
    try:
        action()
    except ProxySourceError as exc:
        require(exc.code == code and str(exc) == code)
    else:
        raise AssertionError


def protocol_error(action: Callable[[], Any],
                   code: str = "agent_rejected") -> None:
    try:
        action()
    except ProxyProtocolError as exc:
        require(exc.code == code and str(exc) == code)
    else:
        raise AssertionError


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def proxy_types(compiled: Any) -> List[str]:
    return [item["type"] for item in compiled.config["proxies"]]


@case("endpointHttpAndSocks")
def endpoint_http_and_socks() -> None:
    http = compile_source(
        "endpoint", "https://user%40example:p%3Aass@proxy.example:8443#web",
        udp_allowed=False,
    )
    node = http.config["proxies"][0]
    require(node == {
        "name": "web", "password": "p:ass", "port": 8443,
        "server": "proxy.example", "tls": True, "type": "http",
        "username": "user@example",
    })
    socks = compile_source(
        "endpoint", "socks5h://user:pass@socks.example:1080#socks", udp_allowed=True
    )
    require(socks.config["proxies"][0]["udp"] is True)
    require(socks.node_names == ("socks",))


@case("uriProtocolsAndSelection")
def uri_protocols_and_selection() -> None:
    identifier = "10000000-0000-4000-8000-000000000001"
    ss_user = b64(b"aes-128-gcm:secret")
    ssr_password = b64(b"secret")
    ssr_remarks = b64(b"ssr")
    ssr_payload = b64(
        ("ssr.example:443:origin:aes-128-gcm:plain:{}/?remarks={}"
         .format(ssr_password, ssr_remarks)).encode("utf-8")
    )
    vmess = b64(json.dumps({
        "v": "2", "ps": "vmess", "add": "vmess.example", "port": "443",
        "id": identifier, "aid": "0", "scy": "auto", "net": "ws",
        "host": "cdn.example", "path": "/ws", "tls": "tls",
        "sni": "vmess.example",
    }, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    source = "\n".join([
        "socks5://u:p@socks.example:1080#socks",
        "ss://{}@ss.example:443#ss".format(ss_user),
        "ssr://{}".format(ssr_payload),
        "trojan://secret@trojan.example:443?sni=trojan.example&type=ws&path=%2Fws&host=cdn.example#trojan",
        "vmess://{}".format(vmess),
        "vless://{}@vless.example:443?encryption=none&security=tls&sni=vless.example&type=grpc&serviceName=svc#vless".format(identifier),
        "hysteria://auth@hysteria.example:443?sni=hysteria.example&upmbps=20&downmbps=50#hysteria",
        "hysteria2://secret@hy2.example:443?sni=hy2.example&obfs=salamander&obfs-password=obfs#hy2",
        "tuic://{}:secret@tuic.example:443?sni=tuic.example&congestion_control=bbr&udp_relay_mode=native#tuic".format(identifier),
        "anytls://secret@anytls.example:443?sni=anytls.example&fp=chrome#anytls",
    ])
    compiled = compile_source("uri_list", source, selected_node="tuic")
    require(proxy_types(compiled) == [
        "socks5", "ss", "ssr", "trojan", "vmess", "vless", "hysteria",
        "hysteria2", "tuic", "anytls",
    ])
    require(compiled.config["proxy-groups"][1]["proxies"][0] == "tuic")
    require(all(node.get("udp") is True for node in compiled.config["proxies"]))


@case("fetchedSubscriptionDetection")
def fetched_subscription_detection() -> None:
    uri_body = b64(b"socks5://u:p@socks.example:1080#one\n")
    compiled = proxy_source.compile_fetched_subscription(uri_body)
    require(compiled.node_names == ("one",))
    clash_body = json.dumps({"proxies": [{
        "name": "two", "type": "socks5", "server": "proxy.example",
        "port": 1080,
    }]})
    compiled = proxy_source.compile_fetched_subscription(clash_body)
    require(compiled.node_names == ("two",))
    source_error("source_invalid", lambda: compile_source(
        "subscription", "https://source.example/list"
    ))


@case("clashInlineProviderAndSnell")
def clash_inline_provider_and_snell() -> None:
    document = {
        "mode": "rule",
        "rules": ["MATCH,DIRECT"],
        "proxy-groups": [{"name": "unsafe", "type": "select", "proxies": ["DIRECT"]}],
        "cfw-bypass": ["localhost", "*.example"],
        "cfw-latency-timeout": 5000,
        "proxies": [{
            "name": "web", "type": "http", "server": "web.example",
            "port": 8080, "username": "u", "password": "p",
        }],
        "proxy-providers": {
            "inline": {
                "type": "inline",
                "payload": [{
                    "name": "snell", "type": "snell", "server": "snell.example",
                    "port": 443, "psk": "key", "version": 3,
                    "obfs-opts": {"mode": "tls", "host": "front.example"},
                }],
            }
        },
    }
    compiled = compile_source("clash", document, udp_allowed=False,
                              selected_node="snell")
    require(proxy_types(compiled) == ["http", "snell"])
    encoded = json.dumps(compiled.config, sort_keys=True, separators=(",", ":"))
    require(all("DIRECT" not in group["proxies"]
                for group in compiled.config["proxy-groups"]))
    require(compiled.config["rules"] == ["MATCH,GLOBAL"])
    require("cfw-bypass" not in encoded and "cfw-latency-timeout" not in encoded)
    require("empty-fallback" not in encoded)


@case("remoteProviderInjectedOnly")
def remote_provider_injected_only() -> None:
    parent = {
        "proxy-providers": {
            "remote": {"type": "http", "url": "https://provider.example/list"}
        }
    }
    fetched: List[str] = []

    def fetch(url: str) -> str:
        fetched.append(url)
        return json.dumps({"proxies": [{
            "name": "remote", "type": "socks5", "server": "remote.example",
            "port": 1080, "udp": True,
        }]})

    compiled = compile_source("clash", parent, fetcher=fetch)
    require(fetched == ["https://provider.example/list"])
    require(compiled.node_names == ("remote",))
    source_error("source_fetch_denied",
                 lambda: compile_source("clash", parent))
    with_header = copy.deepcopy(parent)
    with_header["proxy-providers"]["remote"]["header"] = {
        "User-Agent": "provider-client"
    }
    observed_headers: List[Any] = []

    def fetch_with_header(url: str, *, headers: Any) -> str:
        observed_headers.append(headers)
        return fetch(url)

    require(compile_source(
        "clash", with_header, fetcher=fetch_with_header
    ).node_names == ("remote",))
    require(observed_headers == [{"User-Agent": "provider-client"}])
    source_error(
        "source_fetch_denied",
        lambda: compile_source("clash", with_header, fetcher=fetch),
    )
    authorization = copy.deepcopy(parent)
    authorization["proxy-providers"]["remote"]["header"] = {
        "Authorization": "fixture"
    }
    source_error(
        "source_invalid",
        lambda: compile_source("clash", authorization, fetcher=fetch_with_header),
    )


@case("deterministicControlledConfig")
def deterministic_controlled_config() -> None:
    source = "socks5://u:p@socks.example:1080#node"
    first = compile_source("endpoint", source)
    second = compile_source("endpoint", source)
    require(first == second)
    require(first.source_sha256 ==
            __import__("hashlib").sha256(source.encode("utf-8")).hexdigest())
    config = first.config
    require(config["mode"] == "global")
    require(config["tun"] == {"enable": False})
    require(config["iptables"] == {"enable": False})
    require(config["allow-lan"] is True)
    require(config["bind-address"] == "*")
    require(config["find-process-mode"] == "off")
    require(config["listeners"] == [
        {"listen": "0.0.0.0", "name": "xenoid-redir-v4",
         "port": 7893, "type": "redir"},
        {"listen": "::", "name": "xenoid-redir-v6",
         "port": 7895, "type": "redir"},
        {"listen": "0.0.0.0", "name": "xenoid-tproxy-v4",
         "port": 7897, "type": "tproxy", "udp": True},
        {"listen": "::", "name": "xenoid-tproxy-v6",
         "port": 7899, "type": "tproxy", "udp": True},
    ])
    require(config["dns"]["listen"] == "[::]:1053")
    require(config["dns"]["ipv6"] is True)
    require(all("empty-fallback" not in group
                for group in config["proxy-groups"]))
    require(config["external-controller"].startswith("127.0.0.1:"))
    controller_secret = config.get("secret")
    require(isinstance(controller_secret, str) and len(controller_secret) == 64)
    require(all(character in "0123456789abcdef"
                for character in controller_secret))
    require(controller_secret != first.source_sha256)
    require(all("DIRECT" not in group["proxies"]
                for group in config["proxy-groups"]))


@case("udpPolicy")
def udp_policy() -> None:
    source_error("source_invalid", lambda: compile_source(
        "endpoint", "http://web.example:8080#web"))
    web = compile_source(
        "endpoint", "http://web.example:8080#web", udp_allowed=False)
    require("udp" not in web.config["proxies"][0])
    require(compile_source(
        "endpoint", "http://web.example:8080#web",
        udp_allowed=False,
        allow_insecure_http=False,
    ).node_names == ("web",))
    socks = compile_source("endpoint", "socks5://socks.example:1080#socks",
                           udp_allowed=False)
    require(socks.config["proxies"][0]["udp"] is False)
    clash_http = {"proxies": [{"name": "web", "type": "http",
                                "server": "web.example", "port": 80}]}
    require(compile_source("clash", clash_http).node_names == ("web",))
    clash_http["proxies"][0]["udp"] = True
    source_error("source_invalid", lambda: compile_source("clash", clash_http))


def completed_proxy_status(check_id: int = 9) -> Dict[str, Any]:
    capabilities = {
        "v4DnsProxy": True,
        "v4TcpProxy": True,
        "v4UdpProxy": False,
        "v6DnsProxy": True,
        "v6TcpProxy": True,
        "v6UdpProxy": False,
    }
    return {
        "ok": True,
        "enabled": True,
        "generation": 7,
        "checkId": check_id,
        "runtimeEpoch": "v1-resource-epoch",
        "udpAllowed": False,
        "probe": {
            "checkId": check_id,
            "capabilities": capabilities,
            "elapsedMs": 1200,
            "errorCode": "",
        },
        "report": {
            "generation": 7,
            "checkId": check_id,
            "phase": "active",
            "structuralApplied": True,
            "dataPlaneVerified": True,
            "capabilities": capabilities,
        },
    }


class PendingCheckDaemon:
    def __init__(self) -> None:
        self.status_calls = 0
        self.check_calls = 0

    def proxy_status(self) -> Dict[str, Any]:
        self.status_calls += 1
        status = completed_proxy_status()
        if self.status_calls < 4:
            status["probe"] = None
            status["report"] = {
                "generation": 7,
                "checkId": 9,
                "phase": "staging",
                "structuralApplied": False,
                "dataPlaneVerified": False,
            }
        return copy.deepcopy(status)

    def proxy_check(self) -> Dict[str, Any]:
        self.check_calls += 1
        return {"ok": True, "generation": 7, "checkId": 10}


@case("pendingCheckIsNotSuperseded")
def pending_check_is_not_superseded() -> None:
    daemon = PendingCheckDaemon()
    controller = object.__new__(ProxyController)
    controller._daemon = daemon
    controller._ensure_agent = lambda status: {"ok": True}
    controller._manager_call = lambda *args, **kwargs: {"ok": True}
    result = controller._converge(
        {"ok": True, "generation": 7, "checkId": 9},
        fresh_check=True,
    )
    require(result.get("checkCompleted") is True)
    require(result.get("checkId") == 9)
    require(daemon.check_calls == 0)


@case("daemonCheckCapabilitySchema")
def daemon_check_capability_schema() -> None:
    valid = completed_proxy_status()
    daemon = PendingCheckDaemon()
    daemon.proxy_status = lambda: copy.deepcopy(valid)
    require(wait_for_proxy_check(
        daemon,
        timeout=0,
        expected_check_id=9,
        expected_generation=7,
        expected_runtime_epoch="v1-resource-epoch",
    ).get("checkCompleted") is True)
    legacy = completed_proxy_status()
    legacy["probe"] = {
        "checkId": 9,
        "dnsResolved": True,
        "httpsReached": True,
        "httpStatus": 204,
        "errorCode": "",
    }
    daemon.proxy_status = lambda: copy.deepcopy(legacy)
    result = wait_for_proxy_check(
        daemon,
        timeout=0,
        expected_check_id=9,
        expected_generation=7,
        expected_runtime_epoch="v1-resource-epoch",
    )
    require(result.get("code") == "data_plane_unverified")


@case("malformedUnknownAndPartial")
def malformed_unknown_and_partial() -> None:
    source_error("source_invalid", lambda: compile_source(
        "uri_list", "socks5://socks.example:1080#good\nunknown://opaque#bad"
    ))
    source_error("source_invalid", lambda: compile_source(
        "endpoint", "socks5://u%ZZ:p@socks.example:1080"
    ))
    source_error("source_invalid", lambda: compile_source(
        "uri_list", "vmess://%%%"
    ))


@case("duplicatesNamesAndKeys")
def duplicates_names_and_keys() -> None:
    source_error("source_invalid", lambda: compile_source(
        "uri_list",
        "socks5://one.example:1080#same\nsocks5://two.example:1080#same",
    ))
    duplicate_json = '{"proxies":[],"proxies":[]}'
    source_error("source_invalid", lambda: compile_source("clash", duplicate_json))
    yaml_duplicate = "proxies:\n  - name: one\n    name: two\n    type: socks5\n    server: proxy.example\n    port: 1080\n"
    try:
        compile_source("clash", yaml_duplicate)
    except ProxySourceError as exc:
        require(exc.code in ("source_invalid", "source_dependency_missing"))
    else:
        raise AssertionError


@case("yamlAliasTagAndNodeBound")
def yaml_alias_tag_and_node_bound() -> None:
    documents = (
        "proxies:\n  - &node {name: one, type: socks5, server: proxy.example, port: 1080}\n  - *node\n",
        "proxies: !!seq []\n",
        "cfw-bypass:\n" + "  - item\n" * (proxy_source.MAX_YAML_NODES + 1)
        + "proxies:\n  - {name: one, type: socks5, server: proxy.example, port: 1080}\n",
    )
    for document in documents:
        try:
            compile_source("clash", document)
        except ProxySourceError as exc:
            require(exc.code in ("source_invalid", "source_dependency_missing"))
        else:
            raise AssertionError

    rich_metadata = (
        "cfw-bypass:\n" + "".join(
            "  - host-{:05d}\n".format(index) for index in range(5000)
        )
        + "proxies:\n"
        + "  - {name: one, type: socks5, server: proxy.example, port: 1080}\n"
    )
    try:
        compiled = compile_source("clash", rich_metadata)
    except ProxySourceError as exc:
        if exc.code == "source_dependency_missing":
            return
        raise
    require(compiled.node_names == ("one",))


@case("sourceAndNodeBounds")
def source_and_node_bounds() -> None:
    source_error("source_invalid", lambda: compile_source(
        "uri_list", b"a" * (proxy_source.MAX_SOURCE_BYTES + 1)
    ))
    too_many = {"proxies": [
        {"name": "n{}".format(index), "type": "socks5",
         "server": "proxy.example", "port": 1080}
        for index in range(proxy_source.MAX_NODES + 1)
    ]}
    source_error("source_invalid", lambda: compile_source("clash", too_many))
    long_name = "n" * (proxy_source.MAX_NODE_NAME + 1)
    source_error("source_invalid", lambda: compile_source(
        "endpoint", "socks5://proxy.example:1080#{}".format(long_name)
    ))


@case("selectionAndProviderFailures")
def selection_and_provider_failures() -> None:
    source_error("selection_missing", lambda: compile_source(
        "endpoint", "socks5://proxy.example:1080#one", selected_node="two"
    ))
    source_error("provider_empty", lambda: compile_source("clash", {"proxies": []}))
    source_error("source_invalid", lambda: compile_source("clash", {
        "proxy-providers": {"file": {"type": "file", "path": "/private"}}
    }))


class FakeResponse:
    def __init__(self, status: int, headers: Optional[Dict[str, str]] = None,
                 body: bytes = b""):
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.offset = 0

    def getheader(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self.headers.get(name, default)

    def read(self, amount: int) -> bytes:
        chunk = self.body[self.offset:self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def close(self) -> None:
        pass


class FakePinnedFetcher(PinnedHTTPSFetcher):
    def __init__(self, responses: List[FakeResponse]):
        # Avoid creating or using TLS/network state in this contract test.
        self.timeout = 1.0
        self.ssl_context = None
        self.responses = list(responses)
        self.requests: List[Any] = []

    def _resolve(self, host: str) -> Any:
        return ("93.184.216.34",)

    def _request(self, scheme: str, host: str, port: int, address: str,
                 target: str, headers: Any) -> FakeResponse:
        self.requests.append((scheme, host, port, address, target, dict(headers)))
        return self.responses.pop(0)


@case("fetchUrlAndPrivateRedirect")
def fetch_url_and_private_redirect() -> None:
    source_error("source_fetch_denied", lambda: FakePinnedFetcher([])(
        "https://127.0.0.1/source"
    ))
    source_error("source_fetch_denied", lambda: FakePinnedFetcher([])(
        "https://user:pass@source.example/list"
    ))
    source_error("source_fetch_denied", lambda: FakePinnedFetcher([])(
        "http://source.example/list"
    ))
    source_error("source_fetch_denied", lambda: FakePinnedFetcher([])(
        "https://source.example/list?token=%ZZ"
    ))
    redirect = FakePinnedFetcher([
        FakeResponse(302, {"Location": "https://10.0.0.1/private"}),
    ])
    source_error("source_fetch_denied",
                 lambda: redirect("https://source.example/list"))


@case("fetchMetadataQueryAndHeaderPolicy")
def fetch_metadata_query_and_header_policy() -> None:
    source_error("source_fetch_denied", lambda: FakePinnedFetcher([])(
        "https://source.example/list", headers={"Authorization": "fixture"}
    ))
    fetcher = FakePinnedFetcher([
        FakeResponse(302, {"Location": "https://other.example/final?revision=2"}),
        FakeResponse(200, {
            "Content-Type": "application/yaml", "ETag": "tag",
            "Last-Modified": "Wed, 01 Jan 2025 00:00:00 GMT",
        }, b"proxies: []\n"),
    ])
    result = fetcher(
        "https://source.example/list?token=fixture",
        headers={"User-Agent": "provider-client"},
        etag="old",
    )
    cache_key = proxy_source.fetch_url_cache_key(
        "https://source.example/list?token=fixture")
    require(len(cache_key) == 64 and "fixture" not in cache_key)
    require(cache_key != proxy_source.fetch_url_cache_key(
        "https://source.example/list?token=other"))
    require(result.status == 200 and result.etag == "tag")
    require(fetcher.requests[0][4] == "/list?token=fixture")
    require(fetcher.requests[1][4] == "/final?revision=2")
    require(fetcher.requests[0][5].get("If-None-Match") == "old")
    require("If-None-Match" not in fetcher.requests[1][5])
    require(fetcher.requests[0][5].get("User-Agent") == "provider-client")
    require(fetcher.requests[1][5].get("User-Agent") == "clash.meta")
    insecure = FakePinnedFetcher([
        FakeResponse(200, {"Content-Type": "text/plain"}, b"proxies: []\n")
    ])
    require(insecure(
        "http://source.example/list",
        allow_insecure_http=True,
    ).status == 200)
    require(insecure.requests[0][4] == "/list")
    wrong_type = FakePinnedFetcher([
        FakeResponse(200, {"Content-Type": "text/html"}, b"bad")
    ])
    source_error("source_fetch_denied",
                 lambda: wrong_type("https://source.example/list"))


@case("fetchGzipStreamingCaps")
def fetch_gzip_streaming_caps() -> None:
    plain = b"proxies: []\n"
    compressed = gzip.compress(plain, mtime=0)
    fetcher = FakePinnedFetcher([
        FakeResponse(200, {
            "Content-Type": "application/yaml",
            "Content-Encoding": "gzip",
            "Content-Length": str(len(compressed)),
        }, compressed),
    ])
    require(fetcher("https://source.example/list").body == plain)
    require(fetcher.requests[0][5].get("Accept-Encoding") == "gzip")

    expanded = gzip.compress(
        b"x" * (proxy_source.MAX_SOURCE_BYTES + 1), mtime=0)
    source_error("source_fetch_denied", lambda: FakePinnedFetcher([
        FakeResponse(200, {
            "Content-Type": "application/yaml",
            "Content-Encoding": "gzip",
        }, expanded),
    ])("https://source.example/list"))
    first = gzip.compress(b"first", mtime=0)
    second = gzip.compress(b"second", mtime=0)
    for invalid in (
        first + second,
        first + b"trailing",
        first[:-1],
    ):
        source_error("source_fetch_denied", lambda invalid=invalid: FakePinnedFetcher([
            FakeResponse(200, {
                "Content-Type": "application/yaml",
                "Content-Encoding": "gzip",
            }, invalid),
        ])("https://source.example/list"))
    source_error("source_fetch_denied", lambda: FakePinnedFetcher([
        FakeResponse(200, {
            "Content-Type": "application/yaml",
            "Content-Encoding": "br",
        }, b"opaque"),
    ])("https://source.example/list"))
    source_error("source_fetch_denied", lambda: FakePinnedFetcher([
        FakeResponse(200, {
            "Content-Type": "application/yaml",
            "Content-Encoding": "gzip",
            "Content-Length": str(proxy_source.MAX_SOURCE_BYTES + 1),
        }, b""),
    ])("https://source.example/list"))
    source_error("source_fetch_denied", lambda: FakePinnedFetcher([
        FakeResponse(200, {
            "Content-Type": "application/octet-stream",
        }, b"x" * (proxy_source.MAX_SOURCE_BYTES + 1)),
    ])("https://source.example/list"))


MASTER = bytes(range(32))
INSTANCE = "10000000-0000-4000-8000-000000000001"
EPOCH = "20000000000000000000000000000001"
SESSION = "30000000000000000000000000000003"
REQUEST = "40000000000000000000000000000004"
EXPECTED_C2S = "6c240aa268729cd55b0bc4b55709c2ecfe2c0776e5cb932a3469fc4d1bb1fe11"
EXPECTED_S2C = "e0fd41c8eaa78d37548ac1fe6066fd2be2a64b0d7bb90c02a5747902c19435aa"
EXPECTED_REQUEST_CIPHERTEXT = (
    "Igph5O1dNKbtqhS3O2wCi49btHtk/UCia+bKynuLVfAv0EVsmLtJ/xhgy+G8lXY22"
    "LY0wFbfSZBc+k7fZOWCipX3tCDwGFle"
)
EXPECTED_RESPONSE_CIPHERTEXT = (
    "vt8/oXIktgUQmKB1LO/BZMFrduihLwVfixhBSOK2sB+Y6LEUZ2MXopD5brcUtDSB7qVo"
)


def keys() -> Any:
    return (derive_key(MASTER, INSTANCE, EPOCH, "c2s"),
            derive_key(MASTER, INSTANCE, EPOCH, "s2c"))


def cryptography_available() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except ImportError:
        return False
    return True


def dependency_or_continue() -> bool:
    if cryptography_available():
        return True
    c2s, _ = keys()
    protocol_error(lambda: seal_request(
        c2s, INSTANCE, EPOCH, SESSION, 7, REQUEST, "desired", 1700000000, {}
    ), "protocol_dependency_missing")
    return False


@case("aeadFixedCrossLanguageVector")
def aead_fixed_cross_language_vector() -> None:
    c2s, s2c = keys()
    protocol_error(lambda: seal_request(
        c2s, INSTANCE, EPOCH, SESSION, 7, REQUEST, "export", 1700000000, {}
    ))
    protocol_error(lambda: seal_request(
        c2s, INSTANCE, EPOCH, SESSION, 7, REQUEST,
        "desired", 1700000000123, {}
    ))
    require(c2s.hex() == EXPECTED_C2S and s2c.hex() == EXPECTED_S2C)
    if not dependency_or_continue():
        return
    request = seal_request(
        c2s, INSTANCE, EPOCH, SESSION, 7, REQUEST, "desired", 1700000000, {},
    )
    require(request["ciphertext"] == EXPECTED_REQUEST_CIPHERTEXT)
    response = seal_response(
        s2c, INSTANCE, EPOCH, SESSION, 7, REQUEST, 200,
        {"generation": 9}, ok=True,
    )
    require(response["ciphertext"] == EXPECTED_RESPONSE_CIPHERTEXT)


@case("aeadRoundTripAndBinding")
def aead_round_trip_and_binding() -> None:
    if not dependency_or_continue():
        return
    c2s, s2c = keys()
    request = seal_request(c2s, INSTANCE, EPOCH, SESSION, 8, REQUEST,
                           "report", 1700000001, {"ready": True})
    opened = open_request(c2s, request, INSTANCE, EPOCH)
    require(opened == {"operation": "report", "timestamp": 1700000001,
                       "body": {"ready": True}})
    response = seal_response(s2c, INSTANCE, EPOCH, SESSION, 8, REQUEST, 204,
                             {"accepted": True})
    require(open_response(s2c, response, INSTANCE, EPOCH, SESSION, 8,
                          REQUEST) == {
        "ok": True, "body": {"accepted": True}, "status": 204,
    })
    protocol_error(lambda: open_response(
        s2c, response, INSTANCE, EPOCH, SESSION, 8,
        "50000000000000000000000000000005"
    ))


@case("aeadReplayTamperAndDirection")
def aead_replay_tamper_and_direction() -> None:
    if not dependency_or_continue():
        return
    c2s, s2c = keys()
    envelope = seal_request(c2s, INSTANCE, EPOCH, SESSION, 9, REQUEST,
                            "probe", 1700000002, {"check": 1})
    replay = ReplayWindow()
    open_request(c2s, envelope, INSTANCE, EPOCH, replay)
    protocol_error(lambda: open_request(c2s, envelope, INSTANCE, EPOCH, replay))
    tampered = copy.deepcopy(envelope)
    first = tampered["ciphertext"][0]
    tampered["ciphertext"] = ("A" if first != "A" else "B") + tampered["ciphertext"][1:]
    protocol_error(lambda: open_request(c2s, tampered, INSTANCE, EPOCH))
    protocol_error(lambda: open_request(s2c, envelope, INSTANCE, EPOCH))


@case("aeadWrongResponseDirectionAndStatus")
def aead_wrong_response_direction_and_status() -> None:
    if not dependency_or_continue():
        return
    c2s, s2c = keys()
    response = seal_response(s2c, INSTANCE, EPOCH, SESSION, 10, REQUEST, 200,
                             {"ok": 1})
    protocol_error(lambda: open_response(
        c2s, response, INSTANCE, EPOCH, SESSION, 10, REQUEST
    ))
    modified = copy.deepcopy(response)
    modified["status"] = 201
    protocol_error(lambda: open_response(
        s2c, modified, INSTANCE, EPOCH, SESSION, 10, REQUEST
    ))
    modified = copy.deepcopy(response)
    modified["extra"] = True
    protocol_error(lambda: open_response(
        s2c, modified, INSTANCE, EPOCH, SESSION, 10, REQUEST
    ))


@case("aeadSessionCap")
def aead_session_cap() -> None:
    if not dependency_or_continue():
        return
    c2s, _ = keys()
    replay = ReplayWindow()
    for index in range(1, 33):
        session = format(index, "032x")
        request_id = format(index + 100, "032x")
        envelope = seal_request(c2s, INSTANCE, EPOCH, session, 1, request_id,
                                "desired", 1700000000 + index, {})
        open_request(c2s, envelope, INSTANCE, EPOCH, replay)
    session = format(33, "032x")
    request_id = format(133, "032x")
    envelope = seal_request(c2s, INSTANCE, EPOCH, session, 1, request_id,
                            "desired", 1700000033, {})
    protocol_error(lambda: open_request(c2s, envelope, INSTANCE, EPOCH, replay))


def main() -> int:
    results: Dict[str, bool] = {}
    for name, function in CASES.items():
        try:
            function()
        except Exception:
            results[name] = False
        else:
            results[name] = True
    payload = {"ok": all(results.values()), "cases": results}
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
