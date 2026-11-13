import os
import requests

from dotenv import load_dotenv
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")


class AbuseIPDBClient:

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self):

        self.api_key = os.getenv("ABUSEIPDB_API_KEY")

        if not self.api_key:
            raise ValueError(
                "AbuseIPDB API key not configured!"
            )

        self.session = requests.Session()

        self.session.headers.update({
            "Key": self.api_key,
            "Accept": "application/json"
        })

    def check_ip(self, ip: str) -> dict:

        url = f"{self.BASE_URL}/check"

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        try:

            response = self.session.get(
                url,
                params=params,
                timeout=20
            )

            response.raise_for_status()

            result = response.json()

            data = result["data"]

            return {
                "provider": "AbuseIPDB",
                "ip": ip,
                "abuse_confidence_score": data.get(
                    "abuseConfidenceScore"
                ),
                "total_reports": data.get(
                    "totalReports"
                ),
                "country": data.get(
                    "countryCode"
                ),
                "isp": data.get("isp"),
                "last_reported": data.get(
                    "lastReportedAt"
                ),
                "status": "success"
            }

        except requests.HTTPError as error:

            return {
                "provider": "AbuseIPDB",
                "ip": ip,
                "status": "http_error",
                "error": str(error)
            }

        except requests.RequestException as error:

            return {
                "provider": "AbuseIPDB",
                "ip": ip,
                "status": "connection_error",
                "error": str(error)
            }

        except (ValueError, KeyError, TypeError) as error:

            return {
                "provider": "AbuseIPDB",
                "ip": ip,
                "status": "parsing_error",
                "error": str(error)
            }