import pytest
from unittest.mock import patch

from proxy_checker import (
    parse_azenv_to_dict,
    classify_proxy_from_azenv,
    ProxyAnonymity,
)
from proxy_checker.AnonymityResult import AnonymityResult


# ==============================
# 🔹 Sample AZEnv bodies
# ==============================

AZENV_TRANSPARENT = """
<pre>
REMOTE_ADDR = 104.23.175.187
HTTP_X_FORWARDED_FOR = 182.253.116.193
HTTP_CF_CONNECTING_IP = 182.253.116.193
</pre>
"""

AZENV_ANONYMOUS = """
<pre>
REMOTE_ADDR = 104.23.175.187
HTTP_CF_RAY = abc123
HTTP_CDN_LOOP = cloudflare
</pre>
"""

AZENV_ELITE = """
<pre>
REMOTE_ADDR = 104.23.175.187
</pre>
"""

NOT_AZENV = "<html>No pre block</html>"


# ==============================
# 🔹 Unit: parser
# ==============================


def test_parse_azenv_to_dict():
    headers = parse_azenv_to_dict(AZENV_TRANSPARENT)
    assert headers["REMOTE_ADDR"] == "104.23.175.187"
    assert headers["HTTP_X_FORWARDED_FOR"] == "182.253.116.193"


def test_parse_azenv_invalid():
    headers = parse_azenv_to_dict(NOT_AZENV)
    assert headers == {}


# ==============================
# 🔹 Unit: classifier
# ==============================


def test_classify_transparent():
    result = classify_proxy_from_azenv(
        AZENV_TRANSPARENT,
        expected_ip="104.23.175.187",
    )
    assert result.anonymity == "Transparent"
    assert result.remote_addr == "104.23.175.187"
    assert result.public_ip == "182.253.116.193"


def test_classify_anonymous():
    result = classify_proxy_from_azenv(
        AZENV_ANONYMOUS,
        expected_ip="104.23.175.187",
    )
    assert result.anonymity == "Anonymous"


def test_classify_elite():
    result = classify_proxy_from_azenv(
        AZENV_ELITE,
        expected_ip="104.23.175.187",
    )
    assert result.anonymity == "Elite"


def test_classify_invalid():
    result = classify_proxy_from_azenv(NOT_AZENV)
    assert result.anonymity is None


# ==============================
# 🔹 Integration: parse_anonymity
# ==============================


@patch("proxy_checker.get_public_ip", return_value="8.8.8.8")
@patch("proxy_checker.get_device_ip", return_value="192.168.1.1")
def test_parse_anonymity_transparent(mock_device, mock_public):
    pa = ProxyAnonymity()

    result = pa.parse_anonymity(
        body=AZENV_TRANSPARENT,
        proxy="104.23.175.187:8080",
    )

    assert isinstance(result, AnonymityResult)
    assert result.anonymity == "Transparent"
    assert result.device_ip == "192.168.1.1"
    assert result.public_ip == "182.253.116.193"


@patch("proxy_checker.get_public_ip", return_value="8.8.8.8")
@patch("proxy_checker.get_device_ip", return_value="192.168.1.1")
def test_parse_anonymity_anonymous(mock_device, mock_public):
    pa = ProxyAnonymity()

    result = pa.parse_anonymity(
        body=AZENV_ANONYMOUS,
        proxy="104.23.175.187:8080",
    )

    assert result.anonymity == "Anonymous"


@patch("proxy_checker.get_public_ip", return_value="8.8.8.8")
@patch("proxy_checker.get_device_ip", return_value="192.168.1.1")
def test_parse_anonymity_elite(mock_device, mock_public):
    pa = ProxyAnonymity()

    result = pa.parse_anonymity(
        body=AZENV_ELITE,
        proxy="104.23.175.187:8080",
    )

    assert result.anonymity == "Elite"


# ==============================
# 🔹 Fallback logic
# ==============================


@patch("proxy_checker.get_public_ip", return_value="1.1.1.1")
@patch("proxy_checker.get_device_ip", return_value="1.1.1.1")
def test_fallback_transparent(mock_device, mock_public):
    pa = ProxyAnonymity()

    result = pa.parse_anonymity(
        body=NOT_AZENV,
        proxy="1.1.1.1:8080",
    )

    assert result.anonymity == "Transparent"


@patch("proxy_checker.get_public_ip", return_value="8.8.8.8")
@patch("proxy_checker.get_device_ip", return_value="1.1.1.1")
def test_fallback_elite(mock_device, mock_public):
    pa = ProxyAnonymity()

    result = pa.parse_anonymity(
        body="clean body no headers",
        proxy="8.8.8.8:8080",
    )

    assert result.anonymity == "Elite"


if __name__ == "__main__":
    pytest.main([__file__])
