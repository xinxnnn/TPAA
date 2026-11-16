import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'packages'))
from tpaa_runtime.memory_adapter import MemoryEvent
from tpaa_runtime.synthetic_memory_graph import SyntheticMacro, adjudicate


class SyntheticGraphTests(unittest.TestCase):
    def test_shared_typed_nodes_and_tie(self):
        event = MemoryEvent('t', 'read', 'doc', 'pa', 'tool')
        macros = (SyntheticMacro('b', (event,)), SyntheticMacro('a', (event,)))
        decision = adjudicate((event,), macros, interaction_type='internal')
        self.assertEqual(decision.macro_id, 'a')
        self.assertEqual(decision.scores, (('a', 5), ('b', 5)))
        self.assertEqual(adjudicate((event,), macros, interaction_type='external').operation, 'CREATE')
        # Matching values in different node types do not count as shared nodes.
        other = MemoryEvent('read', 't', 'pa', 'tool', 'doc')
        self.assertEqual(adjudicate((other,), macros, interaction_type='internal').operation, 'CREATE')


if __name__ == '__main__':
    unittest.main()
