from __future__ import annotations

import pytest
from pylibsrtp import Policy

from rtphelper.services.decryption_service import DecryptionService


def test_srtp_profile_mapping_for_supported_suites() -> None:
    assert DecryptionService._srtp_profile_for_suite("AES_CM_128_HMAC_SHA1_80") == Policy.SRTP_PROFILE_AES128_CM_SHA1_80
    assert DecryptionService._srtp_profile_for_suite("AES_CM_128_HMAC_SHA1_32") == Policy.SRTP_PROFILE_AES128_CM_SHA1_32
    assert DecryptionService._srtp_profile_for_suite("AEAD_AES_128_GCM") == Policy.SRTP_PROFILE_AEAD_AES_128_GCM
    assert DecryptionService._srtp_profile_for_suite("AEAD_AES_128_GCM_8") == Policy.SRTP_PROFILE_AEAD_AES_128_GCM
    assert DecryptionService._srtp_profile_for_suite("AEAD_AES_256_GCM") == Policy.SRTP_PROFILE_AEAD_AES_256_GCM
    assert DecryptionService._srtp_profile_for_suite("AEAD_AES_256_GCM_8") == Policy.SRTP_PROFILE_AEAD_AES_256_GCM


def test_srtp_profile_mapping_rejects_unknown_suite() -> None:
    with pytest.raises(ValueError):
        DecryptionService._srtp_profile_for_suite("AES_256_CM_HMAC_SHA1_80")
