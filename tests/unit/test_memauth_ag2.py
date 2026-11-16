"""Real AG2 API loop against an explicitly synthetic local model endpoint."""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'packages'))


class AG2MemoryTests(unittest.TestCase):
    def test_real_agent_loop_and_event_adapter(self):
        from ag2 import Agent
        from ag2.config import OpenAICompletionsConfig
        from tpaa_runtime.memauth_agents import AgentBinding, build_pair, interact

        requests = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                requests.append(data)
                payload = {'id': 'synthetic-test', 'object': 'chat.completion', 'created': 1,
                           'model': 'synthetic-local', 'choices': [{'index': 0, 'finish_reason': 'stop',
                           'message': {'role': 'assistant', 'content': 'Synthetic local test reply.'}}],
                           'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}}
                raw = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = OpenAICompletionsConfig(model='synthetic-local', api_key='synthetic-test-key',
                    base_url=f'http://127.0.0.1:{server.server_port}/v1')
            pa, sa = AgentBinding('did:pa:test', 'unissued-test'), AgentBinding('did:sa:test', 'unissued-test')
            agents = build_pair(pa, sa, config=config)
            self.assertTrue(all(isinstance(agent, Agent) for agent in agents))
            events, metadata = asyncio.run(interact(pa, sa, 'Synthetic test task', config=config))
            self.assertEqual(len(requests), 2)
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0].subject, pa.did)
            self.assertTrue(events[1].object.startswith('sha256:'))
            self.assertEqual(metadata['framework'], 'ag2')
            self.assertNotIn('unissued-test', json.dumps(requests))
            from crypto.memauth import pairing_backend as b
            from crypto.memauth.srs import SRS
            from demos.memauth.ag2_memory import run
            srs = SRS(tuple(b.multiply(b.generator(1), 7**i, 1) for i in range(5)),
                      tuple(b.multiply(b.generator(2), 7**i, 2) for i in range(5)))
            trace = asyncio.run(run(srs, 'Synthetic end-to-end task', config=config))
            self.assertTrue(all(trace['checks'].values()))
            self.assertNotEqual(trace['initialCommitment'], trace['currentCommitment'])
            self.assertIn('not executed', trace['fullAuthentication'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
