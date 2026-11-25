from types import SimpleNamespace

import pytest

from loginllama.ip_extractor import IPExtractor


def django(meta):
    return SimpleNamespace(META=meta)


def flask(headers, remote="203.0.113.9"):
    return SimpleNamespace(headers=headers, environ={"REMOTE_ADDR": remote})


def test_no_request_gives_no_ip():
    assert IPExtractor.extract(None) is None


def test_forwarded_for_skips_private_hops():
    request = flask({"X-Forwarded-For": "10.0.0.1, 192.168.1.5, 8.8.8.8, 1.1.1.1"})

    assert IPExtractor.extract(request) == "8.8.8.8"


def test_forwarded_for_all_private_falls_back_to_next_header():
    request = flask({"X-Forwarded-For": "10.0.0.1", "CF-Connecting-IP": "1.1.1.1"})

    assert IPExtractor.extract(request) == "1.1.1.1"


@pytest.mark.parametrize(
    "headers,expected",
    [
        ({"CF-Connecting-IP": "1.1.1.1", "X-Real-IP": "2.2.2.2"}, "1.1.1.1"),
        ({"X-Real-IP": "2.2.2.2", "True-Client-IP": "3.3.3.3"}, "2.2.2.2"),
        ({"True-Client-IP": "3.3.3.3"}, "3.3.3.3"),
    ],
)
def test_header_priority(headers, expected):
    assert IPExtractor.extract(flask(headers)) == expected


def test_private_values_in_single_ip_headers_are_ignored():
    request = flask({"CF-Connecting-IP": "10.1.1.1", "X-Real-IP": "172.16.0.1"})

    assert IPExtractor.extract(request) == "203.0.113.9"


def test_django_reads_meta_headers():
    request = django({"HTTP_X_FORWARDED_FOR": "8.8.8.8", "REMOTE_ADDR": "5.5.5.5"})

    assert IPExtractor.extract(request) == "8.8.8.8"


def test_django_direct_ip_fallback():
    assert IPExtractor.extract(django({"REMOTE_ADDR": "5.5.5.5"})) == "5.5.5.5"


def test_flask_direct_ip_from_environ():
    assert IPExtractor.extract(flask({})) == "203.0.113.9"


def test_fastapi_direct_ip_from_client_host():
    request = SimpleNamespace(
        headers={}, client=SimpleNamespace(host="6.6.6.6"), url="http://x"
    )

    assert IPExtractor.extract(request) == "6.6.6.6"


def test_generic_remote_addr_fallback():
    assert IPExtractor.extract(SimpleNamespace(remote_addr="4.4.4.4")) == "4.4.4.4"


def test_fastapi_without_client_and_no_other_source_gives_none():
    assert IPExtractor.extract(SimpleNamespace(headers={}, client=None)) is None


def test_object_with_nothing_gives_none():
    assert IPExtractor.extract(SimpleNamespace()) is None


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("8.8.8.8", True),
        ("2001:db8::1", True),
        ("256.1.1.1", False),
        ("not-an-ip", False),
        ("10.0.0.1", False),
        ("172.16.5.5", False),
        ("172.32.0.1", True),
        ("192.168.0.1", False),
        ("127.0.0.1", False),
        ("::1", False),
        ("fc00::1", False),
        ("fe80::1", False),
    ],
)
def test_public_ip_check(ip, expected):
    assert IPExtractor._is_valid_public_ip(ip) is expected
