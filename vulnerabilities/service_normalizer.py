def normalize_service(raw_service):
    raw_service = raw_service or {}

    return {
        "host": raw_service.get("host") or raw_service.get("ip"),
        "hostname": raw_service.get("hostname"),
        "asset_id": raw_service.get("asset_id"),
        "port": _normalize_port(raw_service.get("port")),
        "protocol": _lower_or_default(raw_service.get("protocol"), "tcp"),
        "service": _lower_or_default(raw_service.get("service") or raw_service.get("name")),
        "product": _lower_or_default(raw_service.get("product")),
        "version": _clean_text(raw_service.get("version")),
    }


def _normalize_port(value):
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def _lower_or_default(value, default=None):
    clean = _clean_text(value)
    return clean.lower() if clean else default


def _clean_text(value):
    if value is None:
        return None

    value = str(value).strip()
    return value or None
