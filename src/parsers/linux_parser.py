import re


class LinuxParser:

    LOG_PATTERN = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
        r"\s+(?P<hostname>\S+)"
        r"\s+(?P<process>[\w./-]+)"
        r"(?:\[(?P<pid>\d+)\])?:"
        r"\s+(?P<message>.*)$"
    )

    FAILED_LOGIN = re.compile(
        r"Failed password for "
        r"(?:invalid user )?"
        r"(?P<username>\S+) "
        r"from (?P<ip>\S+)"
    )

    ACCEPTED_LOGIN = re.compile(
        r"Accepted \S+ for "
        r"(?P<username>\S+) "
        r"from (?P<ip>\S+)"
    )

    INVALID_USER = re.compile(
        r"Invalid user (?P<username>\S+) "
        r"from (?P<ip>\S+)"
    )

    def parse_line(self, line: str) -> dict:

        match = self.LOG_PATTERN.match(line)

        if not match:
            return {
                "event_type": "UNKNOWN",
                "raw_log": line
            }

        data = match.groupdict()

        message = data["message"]

        event = {
            "timestamp": data["timestamp"],
            "hostname": data["hostname"],
            "process": data["process"],
            "pid": data["pid"],
            "message": message,
            "event_type": "OTHER",
            "username": None,
            "source_ip": None
        }

        failed = self.FAILED_LOGIN.search(message)
        accepted = self.ACCEPTED_LOGIN.search(message)
        invalid = self.INVALID_USER.search(message)

        if failed:

            event["event_type"] = "FAILED_LOGIN"
            event["username"] = failed.group("username")
            event["source_ip"] = failed.group("ip")

        elif accepted:

            event["event_type"] = "SUCCESSFUL_LOGIN"
            event["username"] = accepted.group("username")
            event["source_ip"] = accepted.group("ip")

        elif invalid:

            event["event_type"] = "INVALID_USER"
            event["username"] = invalid.group("username")
            event["source_ip"] = invalid.group("ip")

        return event

    def parse_logs(self, lines: list[str]) -> list[dict]:

        return [
            self.parse_line(line)
            for line in lines
        ]