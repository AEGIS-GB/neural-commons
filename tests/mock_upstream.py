#!/usr/bin/env python3
"""Mock upstream LLM server for proxy_test.sh.

Returns canned OpenAI- and Anthropic-format responses so tests can run
without hitting real APIs.  Start before running proxy_test.sh:

    python3 tests/mock_upstream.py 18888 &

Then point the Aegis proxy's upstream_url at http://127.0.0.1:18888.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys


class MockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        req = json.loads(body) if body else {}

        stream = req.get("stream", False)

        if self.path == "/v1/messages":  # Anthropic
            resp = {
                "id": "msg_mock",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Mock response"}],
                "model": "mock",
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())

        elif stream:  # OpenAI streaming
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            chunk = {
                "id": "chatcmpl-mock",
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant", "content": "Mock response"},
                        "finish_reason": None,
                    }
                ],
                "model": "mock",
            }
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            done_chunk = {
                "id": "chatcmpl-mock",
                "object": "chat.completion.chunk",
                "choices": [
                    {"index": 0, "delta": {}, "finish_reason": "stop"}
                ],
                "model": "mock",
            }
            self.wfile.write(f"data: {json.dumps(done_chunk)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")

        else:  # OpenAI /v1/chat/completions (non-streaming)
            resp = {
                "id": "chatcmpl-mock",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Mock response",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "model": "mock",
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "total_tokens": 15,
                },
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())

    def do_GET(self):
        if "/models" in self.path:
            resp = {"data": [{"id": "mock-model", "object": "model"}]}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress request logging


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18888
    server = HTTPServer(("127.0.0.1", port), MockHandler)
    print(f"Mock upstream listening on 127.0.0.1:{port}")
    server.serve_forever()
