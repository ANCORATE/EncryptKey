import contextlib
import getpass
import io
import os
import tempfile
import unittest

import keymanager


class KeyManagerTests(unittest.TestCase):
    def test_init_add_get_list_remove(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(path)

        pw = "mypassword"
        secret = "s3cr3t!"

        # init: password twice
        answers = iter([pw, pw])
        getpass.getpass = lambda prompt="": next(answers)
        self.assertEqual(keymanager.cmd_init(path), 0)

        # add: master password + secret
        answers = iter([pw, secret])
        getpass.getpass = lambda prompt="": next(answers)
        self.assertEqual(keymanager.cmd_add(path, "github"), 0)

        # get
        answers = iter([pw])
        getpass.getpass = lambda prompt="": next(answers)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(keymanager.cmd_get(path, "github"), 0)
        self.assertEqual(buf.getvalue().strip(), secret)

        # list
        answers = iter([pw])
        getpass.getpass = lambda prompt="": next(answers)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(keymanager.cmd_list(path), 0)
        self.assertIn("github", buf.getvalue())

        # remove
        answers = iter([pw])
        getpass.getpass = lambda prompt="": next(answers)
        self.assertEqual(keymanager.cmd_remove(path, "github"), 0)

        os.remove(path)


if __name__ == "__main__":
    unittest.main()
