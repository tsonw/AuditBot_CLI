ALIAS_MAP = {
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "open ssh": ("openbsd", "openssh"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
}


def build_cpe_candidates(product, version):
    normalized_product = _normalize_product(product)
    if not normalized_product:
        return []

    alias = ALIAS_MAP.get(normalized_product)
    if not alias:
        return []

    vendor, cpe_product = alias
    candidates = []

    if version:
        candidates.append(_format_cpe(vendor, cpe_product, str(version).strip()))

    candidates.append(_format_cpe(vendor, cpe_product, "*"))
    return candidates


def _format_cpe(vendor, product, version):
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _normalize_product(product):
    if not product:
        return None

    value = str(product).strip().lower()
    value = value.replace("_", " ")

    if value.startswith("apache httpd"):
        return "apache httpd"

    return value
