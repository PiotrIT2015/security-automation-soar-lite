class ThreatScorer:

    def __init__(self, severity_rules):

        self.severity_rules = severity_rules

    def calculate_score(self, triggered_rules):

        score = sum(
            rule["score"]
            for rule in triggered_rules
        )

        return min(score, 100)

    def classify_severity(self, score):

        if score >= self.severity_rules["critical"]:
            return "CRITICAL"

        elif score >= self.severity_rules["high"]:
            return "HIGH"

        elif score >= self.severity_rules["medium"]:
            return "MEDIUM"

        return "LOW"

    def analyze(self, triggered_rules):

        score = self.calculate_score(triggered_rules)

        severity = self.classify_severity(score)

        return {
            "threat_score": score,
            "severity": severity,
            "triggered_rules": triggered_rules
        }