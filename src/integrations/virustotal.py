import os
import requests

from dotenv import load_dotenv
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")


class VirusTotalClient:

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):

        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")

        if not self.api_key:
            raise ValueError(
                "VirusTotal API key not configured!"
            )

        self.session = requests.Session()

        self.session.headers.update({
            "x-apikey": self.api_key,
            "accept": "application/json"
        })

    def check_ip(self, ip: str) -> dict:

        url = f"{self.BASE_URL}/ip_addresses/{ip}"

        try:

            response = self.session.get(
                url,
                timeout=20
            )

            response.raise_for_status()

            result = response.json()

            attributes = result["data"]["attributes"]

            return {
                "provider": "VirusTotal",
                "ip": ip,
                "reputation": attributes.get("reputation"),
                "country": attributes.get("country"),
                "owner": attributes.get("as_owner"),
                "analysis_stats": attributes.get(
                    "last_analysis_stats", {}
                ),
                "status": "success"
            }

        except requests.HTTPError as error:

            return {
                "provider": "VirusTotal",
                "ip": ip,
                "status": "http_error",
                "error": str(error)
            }

        except requests.RequestException as error:

            return {
                "provider": "VirusTotal",
                "ip": ip,
                "status": "connection_error",
                "error": str(error)
            }

        except (ValueError, KeyError, TypeError) as error:

            return {
                "provider": "VirusTotal",
                "ip": ip,
                "status": "parsing_error",
                "error": str(error)
            }