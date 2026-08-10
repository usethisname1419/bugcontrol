from __future__ import annotations

import asyncio


def main() -> None:
    from bugcontrol.app import run_app

    asyncio.run(run_app())


if __name__ == "__main__":
    main()
