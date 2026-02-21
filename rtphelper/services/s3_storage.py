from __future__ import annotations

import logging
import os
import random
import re
import time
from dataclasses import dataclass
import datetime as dt
from pathlib import Path
from typing import Optional, Any, Dict, List

from rtphelper.size_parser import parse_size_bytes

LOGGER = logging.getLogger(__name__)


def _normalize_endpoint(value: str) -> str:
    endpoint = (value or "").strip()
    if not endpoint:
        return "https://s3.amazonaws.com"
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return endpoint
    return f"https://{endpoint}"


def _split_path_bucket_prefix(path_value: str) -> tuple[str, str]:
    clean = (path_value or "").strip().strip("/")
    if not clean:
        return "", ""
    parts = clean.split("/", 1)
    bucket = parts[0].strip()
    prefix = parts[1].strip("/") if len(parts) > 1 else ""
    return bucket, prefix


@dataclass
class S3Config:
    enabled: bool
    endpoint_url: str
    region: str
    bucket: str
    prefix: str
    access_key_id: str
    secret_access_key: str
    session_token: str

    @classmethod
    def from_env(cls) -> "S3Config":
        mode = os.environ.get("RTPHELPER_STORAGE_MODE", "s3").strip().lower()
        enabled = mode == "s3"

        path_bucket, path_prefix = _split_path_bucket_prefix(
            os.environ.get("RTPHELPER_S3_PATH", "td-cpaas-qa-eu-west-1-s3-dialogicsbc/misc/captures")
        )
        bucket = os.environ.get("RTPHELPER_S3_BUCKET", path_bucket).strip()
        prefix = os.environ.get("RTPHELPER_S3_PREFIX", path_prefix).strip().strip("/")
        endpoint_url = _normalize_endpoint(os.environ.get("RTPHELPER_S3_ENDPOINT", "s3.amazonaws.com"))
        region = os.environ.get("RTPHELPER_S3_REGION", "eu-west-1").strip()

        access_key_id = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
        secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
        session_token = os.environ.get("AWS_SESSION_TOKEN", "").strip()
        return cls(
            enabled=enabled,
            endpoint_url=endpoint_url,
            region=region,
            bucket=bucket,
            prefix=prefix,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
        )

    def ready(self) -> bool:
        return bool(self.enabled and self.bucket and self.access_key_id and self.secret_access_key)


class S3CaptureStorage:
    def __init__(self, cfg: S3Config) -> None:
        self._cfg = cfg
        self._client = None
        self._client_error: Optional[str] = None
        self._last_probe_ok = False
        self._max_pool_connections = max(
            1, int(os.environ.get("RTPHELPER_S3_MAX_POOL_CONNECTIONS", "10") or "10")
        )
        self._multipart_threshold = max(
            5 * 1024 * 1024,
            parse_size_bytes(
                os.environ.get("RTPHELPER_S3_MULTIPART_THRESHOLD_BYTES", "200MB"),
                200 * 1000 * 1000,
            ),
        )
        self._multipart_chunksize = max(
            5 * 1024 * 1024,
            parse_size_bytes(
                os.environ.get("RTPHELPER_S3_MULTIPART_CHUNKSIZE_BYTES", "100MB"),
                100 * 1000 * 1000,
            ),
        )
        self._multipart_max_concurrency = max(
            1, int(os.environ.get("RTPHELPER_S3_MULTIPART_MAX_CONCURRENCY", "10") or "10")
        )
        self._multipart_use_threads = (
            os.environ.get("RTPHELPER_S3_MULTIPART_USE_THREADS", "1").strip().lower()
            not in {"0", "false", "no"}
        )

    @property
    def enabled(self) -> bool:
        return self._cfg.enabled

    @property
    def configured(self) -> bool:
        return self._cfg.ready()

    @property
    def bucket(self) -> str:
        return self._cfg.bucket

    @property
    def prefix(self) -> str:
        return self._cfg.prefix

    def _build_client(self):
        if self._client is not None:
            return self._client
        if not self._cfg.ready():
            raise RuntimeError("S3 is not fully configured (bucket and AWS credentials are required)")
        try:
            import boto3  # type: ignore
            from botocore.config import Config as BotocoreConfig  # type: ignore
        except Exception as exc:
            raise RuntimeError("boto3 is not installed") from exc
        self._client = boto3.client(
            "s3",
            endpoint_url=self._cfg.endpoint_url,
            region_name=self._cfg.region or None,
            aws_access_key_id=self._cfg.access_key_id,
            aws_secret_access_key=self._cfg.secret_access_key,
            aws_session_token=self._cfg.session_token or None,
            config=BotocoreConfig(
                s3={"addressing_style": "virtual"},
                max_pool_connections=self._max_pool_connections,
            ),
        )
        return self._client

    def set_max_pool_connections(self, value: int) -> bool:
        """
        Update S3 HTTP connection pool size and force client rebuild if changed.
        Returns True when value changed.
        """
        target = max(1, int(value or 1))
        if target == self._max_pool_connections:
            return False
        self._max_pool_connections = target
        self._client = None
        LOGGER.info(
            "S3 connection pool updated max_pool_connections=%s",
            self._max_pool_connections,
            extra={"category": "CONFIG"},
        )
        return True

    def _extract_region_from_exception(self, exc: Exception) -> str:
        # Try botocore structured response first.
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            err = response.get("Error")
            if isinstance(err, dict):
                for key in ("Region", "BucketRegion"):
                    val = str(err.get(key) or "").strip()
                    if val:
                        return val
            meta = response.get("ResponseMetadata")
            if isinstance(meta, dict):
                headers = meta.get("HTTPHeaders")
                if isinstance(headers, dict):
                    val = str(headers.get("x-amz-bucket-region") or "").strip()
                    if val:
                        return val
        # Fallback to plain message parsing.
        msg = str(exc)
        m = re.search(r"\bs3[.-]([a-z0-9-]+)\.amazonaws\.com\b", msg, re.IGNORECASE)
        if m:
            return m.group(1).strip().lower()
        return ""

    def _switch_region_endpoint(self, region: str) -> bool:
        reg = (region or "").strip().lower()
        if not reg:
            return False
        endpoint = f"https://s3.{reg}.amazonaws.com"
        changed = endpoint != self._cfg.endpoint_url or reg != self._cfg.region
        if not changed:
            return False
        self._cfg.endpoint_url = endpoint
        self._cfg.region = reg
        self._client = None
        LOGGER.warning(
            "S3 endpoint adjusted to regional endpoint endpoint=%s region=%s",
            endpoint,
            reg,
            extra={"category": "CONFIG"},
        )
        return True

    def probe(self) -> None:
        client = self._build_client()
        client.head_bucket(Bucket=self._cfg.bucket)
        self._last_probe_ok = True
        self._client_error = None

    def to_s3_key(self, relative_file: str) -> str:
        rel = relative_file.strip().lstrip("/")
        if not self._cfg.prefix:
            return rel
        return f"{self._cfg.prefix}/{rel}"

    def upload_file(self, local_path: Path, relative_file: str) -> str:
        key = self.to_s3_key(relative_file)
        attempts = int(os.environ.get("RTPHELPER_S3_UPLOAD_MAX_ATTEMPTS", "5") or "5")
        base_delay = float(os.environ.get("RTPHELPER_S3_UPLOAD_RETRY_BASE_SECONDS", "0.4") or "0.4")
        size = int(local_path.stat().st_size)
        last_exc: Exception | None = None

        for attempt in range(1, max(1, attempts) + 1):
            client = self._build_client()
            try:
                try:
                    from boto3.s3.transfer import TransferConfig as S3TransferConfig  # type: ignore
                except Exception:
                    S3TransferConfig = None  # type: ignore
                transfer_cfg = (
                    S3TransferConfig(
                        multipart_threshold=self._multipart_threshold,
                        multipart_chunksize=self._multipart_chunksize,
                        max_concurrency=self._multipart_max_concurrency,
                        use_threads=self._multipart_use_threads,
                    )
                    if S3TransferConfig is not None
                    else None
                )
                client.upload_file(
                    str(local_path),
                    self._cfg.bucket,
                    key,
                    ExtraArgs={"ChecksumAlgorithm": "SHA256"},
                    Config=transfer_cfg,
                )
                head = client.head_object(Bucket=self._cfg.bucket, Key=key)
                remote_size = int(head.get("ContentLength") or 0)
                if remote_size != size:
                    raise RuntimeError(
                        f"S3 size mismatch for {key}: local={size} remote={remote_size}"
                    )
                return key
            except Exception as exc:
                last_exc = exc
                err_text = str(exc)
                should_retarget = ("PermanentRedirect" in err_text) or ("Moved Permanently" in err_text) or ("301" in err_text)
                if should_retarget:
                    region = self._extract_region_from_exception(exc)
                    if self._switch_region_endpoint(region):
                        continue
                rewind_not_seekable = (
                    "need to rewind the stream" in err_text.lower()
                    or "not seekable" in err_text.lower()
                )
                if rewind_not_seekable and attempt < attempts:
                    # Some botocore retry paths fail when rewinding an internal wrapper stream.
                    # Force a fresh client/upload attempt so the file is re-opened cleanly.
                    self._client = None
                    sleep_s = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.25)
                    LOGGER.warning(
                        "Retrying S3 upload after non-seekable stream error attempt=%s/%s key=%s delay_s=%.2f reason=%s",
                        attempt,
                        attempts,
                        key,
                        sleep_s,
                        exc,
                        extra={"category": "FILES"},
                    )
                    time.sleep(sleep_s)
                    continue
                transient = any(
                    token in err_text.lower()
                    for token in (
                        "timeout",
                        "timed out",
                        "temporar",
                        "throttl",
                        "connection reset",
                        "connection aborted",
                        "service unavailable",
                        "internalerror",
                        "slowdown",
                    )
                )
                if transient and attempt < attempts:
                    sleep_s = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.25)
                    LOGGER.warning(
                        "Retrying S3 upload attempt=%s/%s key=%s delay_s=%.2f reason=%s",
                        attempt,
                        attempts,
                        key,
                        sleep_s,
                        exc,
                        extra={"category": "FILES"},
                    )
                    time.sleep(sleep_s)
                    continue
                break

        raise RuntimeError(
            f"Failed to upload {local_path} to {self._cfg.bucket}/{key}: {last_exc}"
        ) from last_exc

    def format_location(self, relative_file: str = "") -> str:
        key = self.to_s3_key(relative_file or "")
        return f"s3://{self._cfg.bucket}/{key}".rstrip("/")

    def format_key_location(self, key: str) -> str:
        clean = (key or "").strip().lstrip("/")
        return f"s3://{self._cfg.bucket}/{clean}".rstrip("/")

    def list_capture_sessions(self, max_keys: int = 5000) -> List[Dict[str, Any]]:
        """
        Scan objects under configured prefix and return discovered capture sessions
        that contain /raw/*.pcap* objects.
        """
        client = self._build_client()
        prefix_root = (self._cfg.prefix.strip("/") + "/") if self._cfg.prefix else ""
        paginator = client.get_paginator("list_objects_v2")
        sessions: Dict[str, Dict[str, Any]] = {}
        seen = 0
        for page in paginator.paginate(Bucket=self._cfg.bucket, Prefix=prefix_root):
            for obj in page.get("Contents", []):
                key = str(obj.get("Key") or "")
                if not key:
                    continue
                low = key.lower()
                if not (low.endswith(".pcap") or low.endswith(".pcapng")):
                    continue
                rel = key[len(prefix_root):] if prefix_root and key.startswith(prefix_root) else key
                parts = [p for p in rel.split("/") if p]
                if "raw" not in parts:
                    continue
                raw_idx = parts.index("raw")
                if raw_idx < 2:
                    continue
                env = parts[0]
                session_id = parts[raw_idx - 1]
                output_dir = "/".join(parts[1:raw_idx - 1]) if raw_idx > 2 else ""
                session_prefix = "/".join(parts[:raw_idx])  # env/.../session/raw
                item = sessions.get(session_prefix)
                lm = obj.get("LastModified")
                if isinstance(lm, dt.datetime):
                    lm_iso = lm.isoformat()
                    lm_ts = lm.timestamp()
                else:
                    lm_iso = None
                    lm_ts = 0.0
                size = int(obj.get("Size") or 0)
                if item is None:
                    item = {
                        "session_prefix": session_prefix,
                        "environment": env,
                        "output_dir": output_dir,
                        "session_id": session_id,
                        "files": 0,
                        "bytes": 0,
                        "last_modified": lm_iso,
                        "_last_ts": lm_ts,
                    }
                    sessions[session_prefix] = item
                item["files"] = int(item["files"]) + 1
                item["bytes"] = int(item["bytes"]) + size
                if lm_ts > float(item.get("_last_ts") or 0.0):
                    item["_last_ts"] = lm_ts
                    item["last_modified"] = lm_iso
                seen += 1
                if seen >= max(1, int(max_keys)):
                    break
            if seen >= max(1, int(max_keys)):
                break
        out = list(sessions.values())
        out.sort(key=lambda x: float(x.get("_last_ts") or 0.0), reverse=True)
        for item in out:
            item.pop("_last_ts", None)
        return out

    def list_session_raw_objects(self, session_prefix: str) -> List[Dict[str, Any]]:
        client = self._build_client()
        rel = str(session_prefix or "").strip().strip("/")
        if not rel:
            return []
        if not rel.endswith("/raw"):
            rel = f"{rel}/raw"
        prefix = self.to_s3_key(rel).rstrip("/") + "/"
        paginator = client.get_paginator("list_objects_v2")
        objects: List[Dict[str, Any]] = []
        for page in paginator.paginate(Bucket=self._cfg.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = str(obj.get("Key") or "")
                if not key:
                    continue
                low = key.lower()
                if not (low.endswith(".pcap") or low.endswith(".pcapng")):
                    continue
                objects.append(
                    {
                        "key": key,
                        "size": int(obj.get("Size") or 0),
                        "last_modified": (
                            obj.get("LastModified").isoformat()
                            if hasattr(obj.get("LastModified"), "isoformat")
                            else None
                        ),
                    }
                )
        objects.sort(key=lambda x: x["key"])
        return objects

    def download_key_to_file(self, key: str, local_path: Path) -> None:
        client = self._build_client()
        local_path.parent.mkdir(parents=True, exist_ok=True)
        client.download_file(self._cfg.bucket, str(key), str(local_path))
