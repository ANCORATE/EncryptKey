# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

import sys


def main():
    if len(sys.argv) == 1:
        from gui import run_gui
        run_gui()
        return 0
    from keymanager import main as cli_main
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())