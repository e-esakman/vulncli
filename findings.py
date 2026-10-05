"""Small, JSON-friendly findings."""


def create_finding(name, severity, description, recommendation):
    """Build a finding with one of the three supported severities."""
    if severity not in ("LOW", "MEDIUM", "HIGH"):
        raise ValueError("Severity must be LOW, MEDIUM, or HIGH")
    return dict(name=name, severity=severity, description=description,
                recommendation=recommendation)
