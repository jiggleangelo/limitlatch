import ast
import pathlib
import unittest


class ConstraintTests(unittest.TestCase):
    def test_agentguard_uses_stdlib_only_and_no_network_clients(self):
        root = pathlib.Path(__file__).parents[1]
        forbidden = {"requests", "httpx", "urllib3", "boto3", "cryptography"}
        for path in (root / "agentguard").glob("*.py"):
            source = path.read_text(encoding="utf-8"); tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import): names = [n.name.split(".")[0] for n in node.names]
                elif isinstance(node, ast.ImportFrom): names = [(node.module or "").split(".")[0]]
                else: continue
                self.assertFalse(forbidden.intersection(names), path)
            self.assertNotIn("urllib.request", source); self.assertNotIn("socket.create_connection", source)


if __name__ == "__main__": unittest.main()
