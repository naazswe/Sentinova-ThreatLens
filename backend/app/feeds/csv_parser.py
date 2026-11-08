import csv
import io

from pydantic import ValidationError

from backend.app.schemas import Indicator


def parse_csv_feed(csv_content: str, source: str):
    """Parse and validate IOC records from CSV content."""

    if not isinstance(csv_content, str) or not csv_content.strip():
        raise ValueError("CSV content cannot be empty")

    reader = csv.DictReader(io.StringIO(csv_content))

    if not reader.fieldnames:
        raise ValueError("CSV must contain a header row")

    reader.fieldnames = [
        name.strip() if name else ""
        for name in reader.fieldnames
    ]

    required_columns = {"indicator_type", "value"}

    if not required_columns.issubset(set(reader.fieldnames)):
        raise ValueError(
            "CSV must contain indicator_type and value columns"
        )

    accepted = []
    rejected = []
    received = 0

    for index, record in enumerate(reader):
        received += 1

        try:
            if None in record:
                raise ValueError("CSV row contains unexpected extra columns")

            indicator_data = {
                **record,
                "source": source,
            }

            indicator = Indicator.model_validate(indicator_data)
            accepted.append(indicator)

        except (ValidationError, TypeError, ValueError) as exc:
            rejected.append({
                "index": index,
                "reason": str(exc),
            })

    return accepted, rejected, received
