from pathlib import Path
from typing import Iterator


class LogCollector:

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)

    def collect(self) -> Iterator[str]:

        if not self.log_path.exists():
            raise FileNotFoundError(
                f"Log file not found: {self.log_path}"
            )

        if not self.log_path.is_file():
            raise ValueError(
                f"Path is not a file: {self.log_path}"
            )

        with self.log_path.open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as log_file:

            for line in log_file:
                line = line.strip()

                if line:
                    yield line

    def collect_all(self) -> list[str]:

        return list(self.collect())