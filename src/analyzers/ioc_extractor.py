import ipaddress


class IOCExtractor:

    def extract_ips(self, events: list[dict]) -> list[dict]:

        extracted = []

        seen = set()

        for event in events:

            ip = event.get("source_ip")

            if not ip:
                continue

            try:
                address = ipaddress.ip_address(ip)

            except ValueError:
                continue

            normalized_ip = str(address)

            if normalized_ip in seen:
                continue

            seen.add(normalized_ip)

            extracted.append({
                "ip": normalized_ip,
                "version": address.version,
                "is_global": address.is_global
            })

        return extracted