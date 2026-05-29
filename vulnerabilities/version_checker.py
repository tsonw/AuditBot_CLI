import re

from packaging.version import InvalidVersion, parse


def is_version_in_range(
    detected_version,
    start_including=None,
    start_excluding=None,
    end_including=None,
    end_excluding=None,
):
    if not detected_version:
        return True

    detected = _parse_version(detected_version)
    if detected is None:
        return False

    checks = (
        (start_including, lambda value: detected >= value),
        (start_excluding, lambda value: detected > value),
        (end_including, lambda value: detected <= value),
        (end_excluding, lambda value: detected < value),
    )

    for raw_value, check in checks:
        if not raw_value:
            continue

        parsed_value = _parse_version(raw_value)
        if parsed_value is None or not check(parsed_value):
            return False

    return True


def _parse_version(value):
    value = str(value).strip()

    try:
        return parse(value)
    except InvalidVersion:
        pass

    # Nmap often returns values like "9.2p1 Debian 2+deb12u10".
    match = re.search(r"\d+(?:\.\d+)*(?:[a-z]\d*)?", value, re.IGNORECASE)
    if not match:
        return None

    try:
        return parse(match.group(0))
    except InvalidVersion:
        return None
