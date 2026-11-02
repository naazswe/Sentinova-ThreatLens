from pydantic import ValidationError

from backend.app.schemas import Indicator


def parse_feed_payload(payload: dict, source: str):
    """
    Validate and normalize indicators received from a threat feed.
    """

    if not isinstance(payload, dict):
        raise ValueError("Feed payload must be a JSON object")

    records = payload.get("indicators")

    if not isinstance(records, list):
        raise ValueError("Feed must contain an indicators list")

    accepted = []
    rejected = []

    for index, record in enumerate(records):
        try:
            if not isinstance(record, dict):
                raise TypeError("Indicator record must be an object")

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

    return accepted, rejected