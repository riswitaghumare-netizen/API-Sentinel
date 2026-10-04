import pytest
from app.core.ssrf import validate_target_url, is_ip_private_or_restricted


def test_ssrf_blocks_cloud_metadata():
    # AWS / GCP / Azure IMDS endpoint
    is_safe, msg = validate_target_url("http://169.254.169.254/latest/meta-data/", allow_local_override=False)
    assert is_safe is False
    assert any(w in msg.lower() for w in ["restricted", "block", "forbidden", "ssrf"])

    # Cloud metadata hostname
    is_safe_host, msg_host = validate_target_url("http://metadata.google.internal/computeMetadata/v1/")
    assert is_safe_host is False
    assert any(w in msg_host.lower() for w in ["restricted", "block", "forbidden", "ssrf"])


def test_ssrf_blocks_invalid_schemes():
    is_safe, msg = validate_target_url("file:///etc/passwd")
    assert is_safe is False
    assert "scheme" in msg.lower()

    is_safe_gopher, _ = validate_target_url("gopher://127.0.0.1:6379/_")
    assert is_safe_gopher is False


def test_ip_restriction_helper():
    assert is_ip_private_or_restricted("127.0.0.1")[0] is True
    assert is_ip_private_or_restricted("10.0.0.1")[0] is True
    assert is_ip_private_or_restricted("192.168.1.1")[0] is True
    assert is_ip_private_or_restricted("172.16.0.5")[0] is True
    assert is_ip_private_or_restricted("169.254.169.254")[0] is True
    assert is_ip_private_or_restricted("8.8.8.8")[0] is False
