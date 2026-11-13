"""Validate only public settings for the disposable learning namespace."""
import json
import sys
from pathlib import Path


def validate(value):
    if set(value) != {"namespace_name", "scenario", "config_revision"}:
        raise ValueError("Unexpected configuration keys")
    if value["namespace_name"] != "tf-devops-lab":
        raise ValueError("Only the isolated tf-devops-lab namespace is allowed")
    if value["scenario"] != "petclinic-devops-study":
        raise ValueError("Unexpected learning scenario")
    if value["config_revision"] not in ["v1", "v2"]:
        raise ValueError("Only v1 or v2 configuration is allowed")


if __name__ == "__main__":
    validate(json.loads(Path(sys.argv[1]).read_text()))
