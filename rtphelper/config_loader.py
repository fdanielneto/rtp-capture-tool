from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

LOGGER = logging.getLogger(__name__)

class RpcapConfig(BaseModel):
    default_port: int = 2002
    auth_mode: str = "null"

    @field_validator("auth_mode", mode="before")
    @classmethod
    def validate_auth_mode(cls, value: object) -> str:
        if value is None:
            return "null"
        if value != "null":
            raise ValueError("Only null authentication is supported")
        return "null"


class AppSettings(BaseModel):
    default_capture_root: Optional[Path] = None

    @field_validator("default_capture_root", mode="before")
    @classmethod
    def normalize_default_capture_root(cls, value: object) -> Optional[Path]:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        return Path(text).expanduser()


class HostConfig(BaseModel):
    id: str
    address: str
    description: str = ""
    sub_region: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    port: Optional[int] = None

    @field_validator("interfaces")
    @classmethod
    def validate_interfaces(cls, interfaces: List[str]) -> List[str]:
        if not interfaces:
            raise ValueError("Host must define at least one interface")
        return interfaces


class RegionConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    hosts: List[HostConfig] = Field(default_factory=list)

    @field_validator("hosts")
    @classmethod
    def validate_hosts(cls, hosts: List[HostConfig]) -> List[HostConfig]:
        if not hosts:
            raise ValueError("Region must include at least one host")
        return hosts


class TopRegionConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    sub_regions: Dict[str, RegionConfig] = Field(default_factory=dict, alias="sub-region")

    @field_validator("sub_regions")
    @classmethod
    def validate_sub_regions(cls, sub_regions: Dict[str, RegionConfig]) -> Dict[str, RegionConfig]:
        if not sub_regions:
            raise ValueError("Region must include at least one sub-region")
        return sub_regions


class EnvironmentConfig(BaseModel):
    regions: Dict[str, TopRegionConfig] = Field(default_factory=dict)


class AppConfig(BaseModel):
    rpcap: RpcapConfig = Field(default_factory=RpcapConfig)
    settings: AppSettings = Field(default_factory=AppSettings)
    environments: Dict[str, EnvironmentConfig] = Field(default_factory=dict)
    # Backward-compatible legacy schema (root regions).
    regions: Dict[str, TopRegionConfig] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def normalize_schema(cls, values: object) -> object:
        if not isinstance(values, dict):
            return values
        data = dict(values)
        envs = data.get("environments")
        regions = data.get("regions")

        # Legacy: regions at root -> treat as QA environment.
        if (not envs) and regions:
            data["environments"] = {
                "PRD": {"regions": {}},
                "QA": {"regions": regions},
                "STG": {"regions": {}},
            }
        return data

    @field_validator("environments")
    @classmethod
    def validate_environments(cls, environments: Dict[str, EnvironmentConfig]) -> Dict[str, EnvironmentConfig]:
        if not environments:
            raise ValueError("At least one environment is required")
        return environments


def load_config(config_path: Path) -> AppConfig:
    LOGGER.info("Loading config path=%s", config_path, extra={"category": "CONFIG"})
    if not config_path.exists():
        raise ValueError(f"Config file not found: {config_path}")

    try:
        parsed = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in config file: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("Configuration root must be a YAML object")

    try:
        cfg = AppConfig.model_validate(parsed)
        LOGGER.info("Config loaded environments=%s", sorted(cfg.environments.keys()), extra={"category": "CONFIG"})
        return cfg
    except ValidationError as exc:
        LOGGER.error("Config validation failed error=%s", exc, extra={"category": "ERRORS"})
        raise ValueError(f"Invalid configuration: {exc}") from exc
