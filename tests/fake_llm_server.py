"""Fake OpenAI-compatible server for end-to-end testing.

Returns a canned forensic analysis response. Run with:
    python tests/fake_llm_server.py

Then test with:
    volai analyze <dump> --provider local --base-url http://localhost:9999/v1
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler

CANNED_REPORT = {
    "summary": (
        "Analysis of the memory dump reveals a Windows 10 x64 system with "
        "signs of suspicious activity. Process svchost.exe (PID 2048) was "
        "spawned from an unusual parent process (PID 1024, cmd.exe), which "
        "is inconsistent with normal Windows behavior where svchost.exe "
        "should be spawned by services.exe.\n\n"
        "Network analysis shows an outbound connection from PID 2048 to "
        "185.220.101.42 on port 443, which is associated with known C2 "
        "infrastructure. Malfind detected injected code in the memory space "
        "of svchost.exe with executable permissions (PAGE_EXECUTE_READWRITE).\n\n"
        "The combination of process injection, anomalous parent-child "
        "relationships, and suspicious network activity strongly suggests "
        "this system has been compromised."
    ),
    "findings": [
        {
            "title": "Suspicious Process Injection in svchost.exe",
            "severity": "critical",
            "description": (
                "Malfind detected injected executable code in PID 2048 "
                "(svchost.exe). The memory region has PAGE_EXECUTE_READWRITE "
                "permissions and contains what appears to be position-independent "
                "shellcode with a MZ header."
            ),
            "evidence": ["PID 2048", "svchost.exe", "PAGE_EXECUTE_READWRITE", "MZ header"],
            "mitre_attack": ["T1055", "T1055.001"],
        },
        {
            "title": "Anomalous Process Parent-Child Relationship",
            "severity": "high",
            "description": (
                "svchost.exe (PID 2048) has cmd.exe (PID 1024) as its parent. "
                "Legitimate svchost.exe instances are spawned by services.exe. "
                "This indicates the process was manually launched or spawned "
                "by an attacker."
            ),
            "evidence": ["PID 2048", "PPID 1024", "svchost.exe", "cmd.exe"],
            "mitre_attack": ["T1036", "T1036.005"],
        },
        {
            "title": "Suspicious Outbound Network Connection",
            "severity": "high",
            "description": (
                "PID 2048 has an established TCP connection to 185.220.101.42:443. "
                "This IP is associated with known command-and-control infrastructure."
            ),
            "evidence": ["PID 2048", "185.220.101.42:443", "ESTABLISHED"],
            "mitre_attack": ["T1071", "T1071.001"],
        },
        {
            "title": "Persistence via Run Key",
            "severity": "medium",
            "description": (
                "Registry analysis shows a suspicious entry in "
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                "pointing to C:\\Users\\admin\\AppData\\Local\\Temp\\update.exe"
            ),
            "evidence": ["HKCU\\...\\Run", "update.exe", "C:\\Users\\admin\\AppData\\Local\\Temp\\"],
            "mitre_attack": ["T1547", "T1547.001"],
        },
    ],
    "risk_score": 85,
    "os_detected": "Windows 10 x64 Build 19041",
    "recommendations": [
        "Immediately isolate this host from the network",
        "Capture full disk image for further analysis",
        "Dump and analyze the injected code from PID 2048",
        "Block 185.220.101.42 at the firewall and check for other connections",
        "Check other hosts for lateral movement indicators",
        "Review authentication logs for the admin account",
        "Submit update.exe to a sandbox for dynamic analysis",
    ],
}


class FakeOpenAIHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        request = json.loads(body)

        # Log what we received
        model = request.get("model", "unknown")
        messages = request.get("messages", [])
        print("\n--- Received request ---")
        print(f"Model: {model}")
        print(f"Messages: {len(messages)}")
        for msg in messages:
            role = msg["role"]
            content_preview = msg["content"][:100]
            print(f"  [{role}] {content_preview}...")

        response = {
            "id": "chatcmpl-fake-test-123",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(CANNED_REPORT),
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 2500,
                "completion_tokens": 800,
                "total_tokens": 3300,
            },
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_GET(self):
        # Handle /v1/models endpoint
        response = {
            "data": [{"id": "fake-model", "object": "model"}]
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        # Quieter logging
        pass


if __name__ == "__main__":
    server = HTTPServer(("localhost", 9999), FakeOpenAIHandler)
    print("Fake OpenAI server running on http://localhost:9999/v1")
    print("Use: volai analyze <dump> --provider local --base-url http://localhost:9999/v1 --model fake")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
