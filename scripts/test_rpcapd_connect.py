#!/usr/bin/env python3
from __future__ import annotations

import argparse
from typing import Sequence

from rtphelper.services.rpcap_client import RpcapClient


def test_rpcap_host(host: str, port: int, timeout: float) -> tuple[bool, str]:
    client = RpcapClient(host=host, port=port, timeout=timeout)
    try:
        client.connect()
        client.auth_null()
        return True, f"[OK] {host}:{port} - ligação RPCAP estabelecida com sucesso"
    except Exception as exc:
        return False, f"[ERRO] {host}:{port} - falha na ligação RPCAP: {exc}"
    finally:
        try:
            client.close()
        except Exception:
            pass


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Testa conectividade rpcapd para um ou mais hosts/IPs.",
    )
    parser.add_argument(
        "hosts",
        nargs="+",
        help="Um ou mais IPs/DNS para testar (ex: 10.10.10.1 host.example.com)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=2002,
        help="Porta do rpcapd (default: 2002)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout de conexão em segundos (default: 5.0)",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    has_failure = False

    for host in args.hosts:
        ok, message = test_rpcap_host(host, args.port, args.timeout)
        print(message)
        if not ok:
            has_failure = True

    return 1 if has_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
