import json
from pathlib import Path

# Function to get data from schema.json based on major type


def get_data(major: str) -> dict:
    base = Path(__file__).resolve().parent
    fp = base / "schema.json"
    with open(fp, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if major not in data:
        raise KeyError(f"Major type '{major}' not found in schema.json")
    return data[major]
