import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import gui  # noqa: E402


def test_gui_imports():
    assert gui.KeyManagerWindow is not None
