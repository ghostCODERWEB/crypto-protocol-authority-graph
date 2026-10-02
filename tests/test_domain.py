import unittest, copy, json
from decimal import Decimal
from pathlib import Path
from cryptolab import analyze
from cryptolab.engine import *

EXAMPLE = json.loads(Path("examples/input.json").read_text())


class DomainTests(unittest.TestCase):
    def test_threshold(self):
        self.assertEqual(analyze(EXAMPLE)["scenarios"][0]["exposed_capabilities"], [])

    def test_delay(self):
        self.assertEqual(analyze(EXAMPLE)["scenarios"][1]["exposed_capabilities"], [])
        self.assertEqual(
            analyze(EXAMPLE)["scenarios"][2]["exposed_capabilities"], ["upgrade"]
        )

    def test_trace(self):
        self.assertEqual(
            [x["rule"] for x in analyze(EXAMPLE)["scenarios"][2]["derivations"]],
            ["2of3", "timelock"],
        )

    def test_duplicate_signer(self):
        d = copy.deepcopy(EXAMPLE)
        d["rules"][0]["sources"] = ["alice", "alice"]
        with self.assertRaises(ValueError):
            analyze(d)

    def test_cycle_terminates(self):
        d = copy.deepcopy(EXAMPLE)
        d["rules"].append(
            {"id": "loop", "sources": ["upgrade"], "target": "safe", "threshold": 1}
        )
        self.assertEqual(analyze(d)["rule_count"], 3)
