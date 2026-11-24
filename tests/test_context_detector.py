from types import SimpleNamespace

import pytest

from loginllama.context_detector import ContextDetector


@pytest.fixture(autouse=True)
def clean_context():
    ContextDetector.clear_context()
    yield
    ContextDetector.clear_context()


DJANGO = SimpleNamespace(
    META={"HTTP_USER_AGENT": "django-ua", "REMOTE_ADDR": "5.5.5.5"}, method="POST"
)
FLASK = SimpleNamespace(
    headers={"User-Agent": "flask-ua"},
    environ={"REMOTE_ADDR": "6.6.6.6"},
    view_args={},
)
FASTAPI = SimpleNamespace(
    headers={"User-Agent": "fastapi-ua"},
    client=SimpleNamespace(host="7.7.7.7"),
    url="http://x",
)


def test_context_is_empty_by_default():
    assert ContextDetector.get_context() is None


@pytest.mark.parametrize(
    "request_obj,framework,ip,user_agent",
    [
        (DJANGO, "django", "5.5.5.5", "django-ua"),
        (FLASK, "flask", "6.6.6.6", "flask-ua"),
        (FASTAPI, "fastapi", "7.7.7.7", "fastapi-ua"),
    ],
)
def test_set_context_captures_request(request_obj, framework, ip, user_agent):
    ContextDetector.set_context(request_obj)

    context = ContextDetector.get_context()
    assert context.framework == framework
    assert context.ip_address == ip
    assert context.user_agent == user_agent
    assert context.raw_request is request_obj


def test_clear_context_removes_it():
    ContextDetector.set_context(DJANGO)
    ContextDetector.clear_context()

    assert ContextDetector.get_context() is None


def test_unrecognised_request_is_unknown_framework():
    assert ContextDetector._detect_framework(SimpleNamespace()) == "unknown"


def test_falsy_request_has_no_framework_or_user_agent():
    assert ContextDetector._detect_framework(None) == "unknown"
    assert ContextDetector._extract_user_agent(None) is None


def test_user_agent_missing_everywhere_gives_none():
    assert ContextDetector._extract_user_agent(SimpleNamespace()) is None
    assert ContextDetector._extract_user_agent(SimpleNamespace(META={})) is None
