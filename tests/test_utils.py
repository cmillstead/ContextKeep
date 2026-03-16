from core.utils import now_timestamp


def test_now_timestamp_format():
    ts = now_timestamp()
    assert "T" in ts
    assert isinstance(ts, str)


def test_now_timestamp_returns_string():
    assert isinstance(now_timestamp(), str)
