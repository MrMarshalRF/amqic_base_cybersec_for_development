"""Linux PTY regression using public synthetic values and temporary files only."""
import os
from pathlib import Path
import select
import shutil
import signal
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux PTY regression")
class TerminalInputTests(unittest.TestCase):
    def run_terminal(self, node, script, arguments, prompts, password):
        import pty

        pid, descriptor = pty.fork()
        if pid == 0:
            try:
                os.execv(node, [node, str(script), *map(str, arguments)])
            except OSError:
                os._exit(127)
        transcript = bytearray()
        cursor = 0
        next_prompt = 0
        reaped = False
        deadline = time.monotonic() + 20
        try:
            while time.monotonic() < deadline:
                readable, _, _ = select.select([descriptor], [], [], 0.05)
                if readable:
                    try:
                        block = os.read(descriptor, 65536)
                    except OSError:
                        block = b""
                    transcript.extend(block)
                if next_prompt < len(prompts):
                    position = transcript.find(prompts[next_prompt], cursor)
                    if position >= 0:
                        cursor = position + len(prompts[next_prompt])
                        # Deliberately no pause after the prompt becomes visible.
                        os.write(descriptor, password + b"\r")
                        next_prompt += 1
                finished, status = os.waitpid(pid, os.WNOHANG)
                if finished:
                    reaped = True
                    while select.select([descriptor], [], [], 0)[0]:
                        try:
                            tail = os.read(descriptor, 65536)
                        except OSError:
                            break
                        if not tail:
                            break
                        transcript.extend(tail)
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                    self.assertEqual(next_prompt, len(prompts))
                    self.assertNotIn(password, transcript)
                    return
            self.fail("Synthetic terminal operation exceeded its deadline")
        finally:
            if not reaped:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(descriptor)

    def test_immediate_input_is_hidden_and_roundtrips(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is required for the terminal regression")
        script = Path(__file__).resolve().with_name("archive_crypto.mjs")
        password = b"PUBLIC_SYNTHETIC_TERMINAL_PASSPHRASE_2026"
        with tempfile.TemporaryDirectory(prefix="amqic-terminal-test-") as directory:
            root = Path(directory)
            original = root / "original"
            original.write_bytes(b"Public synthetic payload\x00\n")
            for attempt in range(5):
                encrypted = root / f"encrypted-{attempt}"
                restored = root / f"restored-{attempt}"
                self.run_terminal(node, script, ["encrypt", original, encrypted],
                                  [b"Archive password: ", b"Repeat: "], password)
                self.run_terminal(node, script, ["decrypt", encrypted, restored],
                                  [b"Archive password: "], password)
                self.assertEqual(restored.read_bytes(), original.read_bytes())


if __name__ == "__main__":
    unittest.main()
