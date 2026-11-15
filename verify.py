import argparse
import json
import sys
from agentguard import verify_bundle


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify an AgentGuard evidence bundle")
    parser.add_argument("bundle")
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--tsa-key-file", required=True)
    args = parser.parse_args(argv)
    try:
        with open(args.bundle, "r", encoding="utf-8") as handle:
            bundle = json.load(handle)
        with open(args.key_file, "rb") as handle:
            key = handle.read()
        with open(args.tsa_key_file, "rb") as handle:
            tsa_key = handle.read()
    except (OSError, ValueError, json.JSONDecodeError):
        print("verification input error; first_bad_seq=None")
        return 1
    try:
        result = verify_bundle(bundle, key, tsa_key)
    except Exception:
        print("verification failed; first_bad_seq=None")
        return 1
    print(f"{result.reason}; first_bad_seq={result.first_bad_seq}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
