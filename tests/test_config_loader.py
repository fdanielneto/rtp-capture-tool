from pathlib import Path

import pytest

from rtphelper.config_loader import load_config


def test_load_config_success(tmp_path: Path) -> None:
    config_file = tmp_path / "hosts.yaml"
    config_file.write_text(
        """
rpcap:
  default_port: 2002
  auth_mode: null
regions:
  US:
    sub-region:
      us-east:
        hosts:
          - id: media-1
            address: 10.10.10.10
            interfaces: ["1"]
""".strip(),
        encoding="utf-8",
    )

    config = load_config(config_file)
    assert config.rpcap.default_port == 2002
    assert "US" in config.regions
    assert config.regions["US"].sub_regions["us-east"].hosts[0].id == "media-1"


def test_load_config_rejects_invalid_auth_mode(tmp_path: Path) -> None:
    config_file = tmp_path / "hosts.yaml"
    config_file.write_text(
        """
rpcap:
  default_port: 2002
  auth_mode: password
regions:
  US:
    sub-region:
      us-east:
        hosts:
          - id: media-1
            address: 10.10.10.10
            interfaces: ["1"]
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_config(config_file)


def test_load_config_accepts_yaml_null_auth_mode(tmp_path: Path) -> None:
    config_file = tmp_path / "hosts.yaml"
    config_file.write_text(
        """
rpcap:
  default_port: 2002
  auth_mode: null
regions:
  US:
    sub-region:
      us-east:
        hosts:
          - id: media-1
            address: 10.10.10.10
            interfaces: ["1"]
""".strip(),
        encoding="utf-8",
    )

    config = load_config(config_file)
    assert config.rpcap.auth_mode == "null"
