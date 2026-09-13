"""Allow ``python -m deaddrop ...`` to invoke the client CLI."""

from .cli import client_main

if __name__ == "__main__":
    raise SystemExit(client_main())
