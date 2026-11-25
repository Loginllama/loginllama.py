import hashlib
import hmac
import sys
from types import SimpleNamespace

import pytest

from loginllama.api import Api, unavailable
from loginllama.context_detector import ContextDetector
from loginllama.loginllama import (
    AuthenticationOutcome,
    LoginCheckStatus,
    LoginLlama,
    verify_webhook_signature,
)


def mock_request(ip: str, user_agent: str):
    class MockRequest:
        META = {
            "HTTP_X_FORWARDED_FOR": ip,
            "REMOTE_ADDR": ip,
            "HTTP_USER_AGENT": user_agent,
        }
        headers = {"User-Agent": user_agent}
        remote_addr = ip

    return MockRequest()


def test_check_valid_login(monkeypatch):
    client = LoginLlama(api_token="mockToken")

    def fake_post(self, url, params):
        assert params["ip_address"] == "192.168.1.1"
        assert params["user_agent"] == "Mozilla/5.0"
        assert params["identity_key"] == "validUser"
        return {
            "status": "success",
            "message": "Valid login",
            "codes": ["login_valid"],
            "risk_score": 2,
            "environment": "staging",
            "meta": {"new_device_login": False},
        }

    monkeypatch.setattr(Api, "post", fake_post)

    result = client.check(
        "validUser",
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0",
    )

    assert result.status == "success"
    assert result.message == "Valid login"
    assert LoginCheckStatus.VALID in result.codes
    assert result.risk_score == 2
    assert result.environment == "staging"
    assert result.meta == {"new_device_login": False}


def test_check_invalid_login_raises(monkeypatch):
    client = LoginLlama(api_token="mockToken")

    def fake_post(self, url, params):
        raise Exception("Login check failed")

    monkeypatch.setattr(Api, "post", fake_post)

    with pytest.raises(Exception) as exc:
        client.check(
            "invalidUser",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

    assert str(exc.value) == "Login check failed"


@pytest.mark.parametrize(
    "identity_key,kwargs,expected_message",
    [
        ("id", {"user_agent": "ua"}, "ip_address could not be detected"),
        ("id", {"ip_address": "ip"}, "user_agent could not be detected"),
        (None, {"ip_address": "ip", "user_agent": "ua"}, "identity_key is required"),
    ],
)
def test_missing_required_fields(identity_key, kwargs, expected_message):
    client = LoginLlama(api_token="mockToken")
    with pytest.raises(ValueError, match=expected_message):
        client.check(identity_key, **kwargs)


def test_extracts_ip_and_user_agent_from_request(monkeypatch):
    client = LoginLlama(api_token="mockToken")

    def fake_post(self, url, params):
        return {
            "status": "success",
            "message": "Valid login",
            "codes": ["login_valid"],
            "risk_score": 1,
            "environment": "production",
        }

    monkeypatch.setattr(Api, "post", fake_post)

    req = mock_request("192.168.1.1", "Mozilla/5.0")
    result = client.check("validUser", request=req)

    assert result.status == "success"
    assert LoginCheckStatus.VALID in result.codes


def test_webhook_signature_verification():
    payload = b'{"event":"login.checked"}'
    secret = "secret"
    signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    assert verify_webhook_signature(payload, signature, secret) is True
    assert verify_webhook_signature(payload, "deadbeef", secret) is False
    assert verify_webhook_signature(payload, signature, "wrong") is False


@pytest.mark.parametrize("method", ["check", "report_success", "report_failure"])
def test_sends_privileged_for_an_admin(monkeypatch, method):
    client = LoginLlama(api_token="mockToken")
    sent = {}

    def fake_post(self, url, params):
        sent.update(params)
        return {"status": "success", "message": "", "codes": [], "risk_score": 0}

    monkeypatch.setattr(Api, "post", fake_post)

    getattr(client, method)(
        "admin@example.test",
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0",
        privileged=True,
    )

    assert sent["privileged"] is True


def stub_post(monkeypatch, response, sent=None):
    def fake_post(self, url, params):
        if sent is not None:
            sent.update(params)
        return response

    monkeypatch.setattr(Api, "post", fake_post)


def test_unknown_codes_stay_strings_and_known_become_enums(monkeypatch):
    stub_post(
        monkeypatch,
        {
            "status": "error",
            "message": "m",
            "codes": ["known_vpn", "brand_new"],
            "risk_score": 80,
            "environment": "production",
        },
    )

    result = LoginLlama(api_token="t").check("u", ip_address="8.8.8.8", user_agent="ua")

    assert result.codes == [LoginCheckStatus.KNOWN_VPN, "brand_new"]
    assert result.risk_score == 80


def test_missing_response_fields_use_defaults(monkeypatch):
    stub_post(monkeypatch, {"status": "success"})

    result = LoginLlama(api_token="t").check("u", ip_address="8.8.8.8", user_agent="ua")

    assert result.codes == []
    assert result.risk_score == 0
    assert result.environment == "production"
    assert result.meta is None


def test_unavailable_result_parses_as_a_zero_risk_check(monkeypatch):
    stub_post(monkeypatch, unavailable("down"))

    result = LoginLlama(api_token="t").check("u", ip_address="8.8.8.8", user_agent="ua")

    assert result.status == "unavailable"
    assert result.risk_score == 0


def test_api_token_comes_from_environment(monkeypatch):
    monkeypatch.setenv("LOGINLLAMA_API_KEY", "from-env")

    assert LoginLlama().api.headers["X-API-KEY"] == "from-env"


def test_missing_api_token_raises(monkeypatch):
    monkeypatch.delenv("LOGINLLAMA_API_KEY", raising=False)

    with pytest.raises(ValueError, match="LOGINLLAMA_API_KEY is required"):
        LoginLlama()


def test_explicit_token_and_base_url_are_used():
    client = LoginLlama(api_token="abc", base_url="https://example.test")

    assert client.api.headers["X-API-KEY"] == "abc"
    assert client.api.base_url == "https://example.test"


@pytest.mark.parametrize(
    "given,expected",
    [
        (AuthenticationOutcome.FAILED, "failed"),
        ("pending", "pending"),
        (None, None),
    ],
)
def test_authentication_outcome_is_sent_as_string(monkeypatch, given, expected):
    sent = {}
    stub_post(monkeypatch, {"status": "success"}, sent)

    LoginLlama(api_token="t").check(
        "u", ip_address="8.8.8.8", user_agent="ua", authentication_outcome=given
    )

    assert sent["authentication_outcome"] == expected


def test_report_helpers_set_outcome(monkeypatch):
    sent = {}
    stub_post(monkeypatch, {"status": "success"}, sent)
    client = LoginLlama(api_token="t")

    client.report_success("u", ip_address="8.8.8.8", user_agent="ua")
    assert sent["authentication_outcome"] == "success"
    client.report_failure("u", ip_address="8.8.8.8", user_agent="ua")
    assert sent["authentication_outcome"] == "failed"


def test_explicit_values_beat_request_and_context(monkeypatch):
    sent = {}
    stub_post(monkeypatch, {"status": "success"}, sent)
    ContextDetector.set_context(mock_request("9.9.9.9", "ctx-ua"))
    try:
        LoginLlama(api_token="t").check(
            "u",
            ip_address="8.8.8.8",
            user_agent="explicit-ua",
            request=mock_request("7.7.7.7", "req-ua"),
        )
    finally:
        ContextDetector.clear_context()

    assert sent["ip_address"] == "8.8.8.8"
    assert sent["user_agent"] == "explicit-ua"


def test_context_supplies_ip_and_user_agent(monkeypatch):
    sent = {}
    stub_post(monkeypatch, {"status": "success"}, sent)
    ContextDetector.set_context(mock_request("9.9.9.9", "ctx-ua"))
    try:
        LoginLlama(api_token="t").check("u")
    finally:
        ContextDetector.clear_context()

    assert sent["ip_address"] == "9.9.9.9"
    assert sent["user_agent"] == "ctx-ua"


def test_request_without_user_agent_falls_through_to_error():
    class Bare:
        META = {"HTTP_X_FORWARDED_FOR": "8.8.8.8"}

    with pytest.raises(ValueError, match="user_agent could not be detected"):
        LoginLlama(api_token="t").check("u", request=Bare())


@pytest.mark.parametrize(
    "request_obj,expected",
    [
        (None, None),
        (SimpleNamespace(headers={"user-agent": "lower"}), "lower"),
        (SimpleNamespace(headers={"User-Agent": "Upper"}), "Upper"),
        (SimpleNamespace(), None),
    ],
)
def test_client_user_agent_extraction(request_obj, expected):
    assert LoginLlama(api_token="t")._extract_user_agent(request_obj) == expected


def test_middleware_stores_flask_request_context(monkeypatch):
    flask_request = SimpleNamespace(
        headers={"X-Forwarded-For": "8.8.4.4", "User-Agent": "flask-ua"},
        environ={},
        view_args={},
    )
    monkeypatch.setitem(sys.modules, "flask", SimpleNamespace(request=flask_request))

    LoginLlama(api_token="t").middleware()()
    try:
        context = ContextDetector.get_context()
        assert context.ip_address == "8.8.4.4"
        assert context.framework == "flask"
    finally:
        ContextDetector.clear_context()


def test_webhook_signature_rejects_missing_inputs():
    assert verify_webhook_signature(b"{}", None, "secret") is False
    assert verify_webhook_signature(b"{}", "", "secret") is False
    assert verify_webhook_signature(b"{}", "abc", "") is False


def test_webhook_signature_accepts_str_payload_and_rejects_tampering():
    payload = '{"event":"login.checked"}'
    signature = hmac.new(b"secret", payload.encode(), hashlib.sha256).hexdigest()

    assert verify_webhook_signature(payload, signature, "secret") is True
    assert verify_webhook_signature(payload + " ", signature, "secret") is False
