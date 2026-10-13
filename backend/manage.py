#!/usr/bin/env python
import os
import sys
from pathlib import Path


def _load_env() -> None:
    """Load .env into os.environ before Django starts.

    Searches for a .env file starting from manage.py's directory and
    walking up to the project root.  Values already present in the OS
    environment are NOT overwritten so that explicit shell exports
    and Docker env_file directives always take precedence.

    No third-party libraries required.
    """
    here = Path(__file__).resolve().parent
    for directory in (here, here.parent):
        env_file = directory / ".env"
        if env_file.is_file():
            try:
                with env_file.open(encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        key, _, value = line.partition("=")
                        key = key.strip()
                        # Strip inline comments (e.g. KEY=value  # comment)
                        # Quoted values are preserved as-is (strip matching quotes only).
                        raw = value.strip()
                        if raw and raw[0] in ('"', "'"):
                            value = raw.strip(raw[0])
                        else:
                            # Unquoted — strip trailing inline comment after whitespace+#
                            value = raw.split("#")[0].rstrip()
                        if key and key not in os.environ:
                            os.environ[key] = value
            except OSError:
                pass
            break  # stop after the first .env found


def main() -> None:
    _load_env()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.development")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
