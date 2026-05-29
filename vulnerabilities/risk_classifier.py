def classify_risk(cvss_score):
    if cvss_score is None:
        return "UNKNOWN"

    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"

    return "UNKNOWN"


def generate_recommendation(service, version, risk):
    service_name = service or "service"
    version_text = f" {version}" if version else ""

    if risk in {"CRITICAL", "HIGH"}:
        return (
            f"Update or patch {service_name}{version_text} immediately. "
            "If the service is not required, disable or remove it."
        )

    if risk == "MEDIUM":
        return (
            f"Review exposure for {service_name}{version_text}, update when possible, "
            "and restrict network access where practical."
        )

    if risk == "LOW":
        return f"Monitor {service_name}{version_text} and keep regular patching in place."

    return f"Manual verification recommended for {service_name}{version_text}."
