def _cve_object(cve_data):
    return cve_data.get("cve", cve_data) if isinstance(cve_data, dict) else {}


def get_english_description(cve_data):
    cve = _cve_object(cve_data)

    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return description.get("value", "")

    descriptions = cve.get("descriptions", [])
    if descriptions:
        return descriptions[0].get("value", "")

    return ""


def get_cvss(cve_data):
    cve = _cve_object(cve_data)
    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_values = metrics.get(key) or []
        if not metric_values:
            continue

        metric = metric_values[0]
        cvss_data = metric.get("cvssData", {})

        return {
            "score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity") or metric.get("baseSeverity"),
            "vector_string": cvss_data.get("vectorString"),
            "version": cvss_data.get("version"),
        }

    return {
        "score": None,
        "severity": None,
        "vector_string": None,
        "version": None,
    }


def get_cwe(cve_data):
    cve = _cve_object(cve_data)

    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value")
            if description.get("lang") == "en" and value:
                return value

    return None


def extract_cpe_matches(cve_data):
    cve = _cve_object(cve_data)
    matches = []

    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            matches.extend(_extract_node_matches(node))

    return matches


def _extract_node_matches(node):
    matches = []

    for cpe_match in node.get("cpeMatch", []):
        matches.append({
            "vulnerable": bool(cpe_match.get("vulnerable", False)),
            "criteria": cpe_match.get("criteria"),
            "matchCriteriaId": cpe_match.get("matchCriteriaId"),
            "versionStartIncluding": cpe_match.get("versionStartIncluding"),
            "versionStartExcluding": cpe_match.get("versionStartExcluding"),
            "versionEndIncluding": cpe_match.get("versionEndIncluding"),
            "versionEndExcluding": cpe_match.get("versionEndExcluding"),
        })

    for child in node.get("children", []):
        matches.extend(_extract_node_matches(child))

    return matches
