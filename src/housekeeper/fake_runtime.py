# SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
# SPDX-License-Identifier: MIT

"""Strict fake Docker/Podman CLI for test_cli.py; never invokes a real runtime."""

import json
import os
from pathlib import Path
import sys
import time
import uuid


def state(image_id="image-1", labels=None):
    return {
        "Id": uuid.uuid4().hex, "Image": image_id,
        "State": {"Running": True, "Restarting": False, "Status": "running",
                  "Error": "", "ExitCode": 0},
        "Config": {"Image": "fixture:testing", "Labels": labels or {}},
    }


def main():
    root = Path(os.environ["EVECTL_FAKE_RUNTIME"])
    args = sys.argv[1:]
    with (root / "commands").open("a") as record:
        record.write(json.dumps([Path(sys.argv[0]).name, *(args or ["<probe>"])]) + "\n")
    if args and args[0] == os.environ.get("EVECTL_FAKE_FAIL"):
        print(os.environ.get("EVECTL_FAKE_ERROR", "permission denied"), file=sys.stderr)
        return 1
    if not args or args == ["--version"]:
        print("fake runtime 5.0.0")
    elif args[0] == "version":
        print(json.dumps({"Client": {"Version": "5.0.0"}, "Version": "5.0.0"}))
    elif args == ["ps", "--all", "--format", "{{.Names}}"]:
        print("\n".join(path.name for path in (root / "containers").iterdir()))
    elif args[:4] == ["image", "inspect", "--format", "{{.Id}}"]:
        assert args[4:] == ["fixture:testing"], args
        print((root / "image-id").read_text())
    elif args[0] == "pull":
        assert args[1:] == ["fixture:testing"], args
    elif args[0] == "inspect":
        if args[1] == "fixture:testing":
            print(json.dumps([{"Id": (root / "image-id").read_text()}]))
        else:
            path = root / "containers" / args[1]
            if not path.is_file():
                return 1
            print("[" + path.read_text() + "]")
    elif args[0] in ("stop", "rm"):
        path = root / "containers" / args[-1]
        if not path.exists():
            return 1
        if args[0] == "rm":
            path.unlink()
        else:
            entry = json.loads(path.read_text())
            entry["State"]["Running"] = False
            entry["State"]["Status"] = "exited"
            temporary = root / ("state-" + str(os.getpid()))
            temporary.write_text(json.dumps(entry))
            temporary.replace(path)
    elif args[0] == "run":
        assert "fixture:testing" in args, args
        if "--check" in args:
            assert "--pull=never" in args, args
        elif "--dump-config" in args:
            print("outputs.0 = eve-log\noutputs.1 = file-store")
        elif "-V" in args:
            print("Suricata version 8.0.6")
        else:
            name = next((arg.split("=", 1)[1] for arg in args
                         if arg.startswith("--name=")), None)
            if name is None:
                name = args[args.index("--name") + 1]
            labels = dict(arg[len("--label="):].split("=", 1) for arg in args
                          if arg.startswith("--label="))
            entry = state((root / "image-id").read_text(), labels)
            path = root / "containers" / name
            path.write_text(json.dumps(entry))
            if "--detach" in args:
                print(entry["Id"])
            else:
                # A real attached client remains alive until its container is
                # stopped. Merely waiting on this child cannot stop it.
                (root / (name + ".ready")).touch()
                deadline = time.monotonic() + 20
                while path.exists() and json.loads(path.read_text())["State"]["Running"]:
                    if time.monotonic() > deadline:
                        return 2
                    time.sleep(0.02)
                (root / (name + ".reaped")).touch()
    elif args[0] == "exec" and args[2:] == ["suricata", "-V"]:
        print("Suricata version " + os.environ.get("EVECTL_FAKE_RUNNING_VERSION", "8.0.6"))
    elif args[0] == "exec" and args[1] == "-d":
        pass  # Record the EVE spool backstop, but do not execute it.
    else:
        raise AssertionError("Unexpected fake runtime command: " + repr(args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
