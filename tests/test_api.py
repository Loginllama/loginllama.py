import pytest
import requests

from loginllama.api import Api

api = Api({"X-API-KEY": "key"}, "https://api.test/v1")


class FakeResponse:
    def __init__(self, status_code, body=None, text=""):
        self.status_code = status_code
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("not JSON")
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}", response=self)


# An outage must not block logins, so post() returns an "unavailable" result
# instead of raising.
@pytest.mark.parametrize(
    "outage",
    [requests.ConnectionError("refused"), requests.Timeout("timed out")],
)
def test_post_fails_open_when_unreachable(monkeypatch, outage):
    def fake_post(*args, **kwargs):
        raise outage

    monkeypatch.setattr(requests, "post", fake_post)

    result = api.post("/login/check")

    assert result["status"] == "unavailable"
    assert result["risk_score"] == 0
    assert result["codes"] == []


def test_post_fails_open_on_server_error(monkeypatch):
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: FakeResponse(502, text="Bad Gateway")
    )

    assert api.post("/login/check")["status"] == "unavailable"


def test_post_gives_up_after_two_seconds(monkeypatch):
    seen = {}

    def fake_post(*args, **kwargs):
        seen["timeout"] = kwargs["timeout"]
        return FakeResponse(200, {"status": "success"})

    monkeypatch.setattr(requests, "post", fake_post)
    api.post("/login/check")

    assert seen["timeout"] == 2


def test_post_still_raises_on_a_client_error(monkeypatch):
    monkeypatch.setattr(
        requests,
        "post",
        lambda *a, **k: FakeResponse(401, {"errors": [{"code": "unauthorized"}]}),
    )

    with pytest.raises(requests.HTTPError):
        api.post("/login/check")


def test_post_returns_parsed_body_on_success(monkeypatch):
    body = {"status": "success", "risk_score": 3}
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse(200, body))

    assert api.post("/login/check") == body


def test_post_fails_open_when_body_is_not_json(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse(200))

    result = api.post("/login/check")

    assert result["status"] == "unavailable"
    assert result["risk_score"] == 0


def test_post_sends_api_key_and_source_headers(monkeypatch):
    seen = {}

    def fake_post(url, **kwargs):
        seen["url"] = url
        seen["headers"] = kwargs["headers"]
        seen["json"] = kwargs["json"]
        return FakeResponse(200, {})

    monkeypatch.setattr(requests, "post", fake_post)
    api.post("/login/check", {"ip_address": "8.8.8.8"})

    assert seen["url"] == "https://api.test/v1/login/check"
    assert seen["headers"]["X-API-KEY"] == "key"
    assert seen["headers"]["X-LOGINLLAMA-SOURCE"] == "python-sdk"
    assert seen["json"] == {"ip_address": "8.8.8.8"}


def test_get_returns_body(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResponse(200, {"ok": True})
    )

    assert api.get("/ping") == {"ok": True}


def test_get_raises_on_error_status(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(500))

    with pytest.raises(requests.HTTPError):
        api.get("/ping")
