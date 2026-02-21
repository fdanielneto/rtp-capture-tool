from rtphelper.size_parser import parse_size_bytes


def test_parse_size_bytes_accepts_plain_integer() -> None:
    assert parse_size_bytes("1000000000", 1) == 1000000000


def test_parse_size_bytes_accepts_decimal_units() -> None:
    assert parse_size_bytes("200MB", 1) == 200_000_000
    assert parse_size_bytes("1GB", 1) == 1_000_000_000


def test_parse_size_bytes_accepts_binary_units() -> None:
    assert parse_size_bytes("100MiB", 1) == 104_857_600
    assert parse_size_bytes("1 GiB", 1) == 1_073_741_824


def test_parse_size_bytes_accepts_fractional_values() -> None:
    assert parse_size_bytes("1.5GB", 1) == 1_500_000_000


def test_parse_size_bytes_falls_back_to_default() -> None:
    assert parse_size_bytes("", 123) == 123
    assert parse_size_bytes("0", 123) == 123
    assert parse_size_bytes("abc", 123) == 123
    assert parse_size_bytes("10XB", 123) == 123
