import http.server
import socketserver
import json
import webbrowser
from pathlib import Path
import os

PORT = 8001
SCRIPT_DIR = Path(__file__).parent
OUTPUT_FILE = SCRIPT_DIR / 'cloudtap_output.json'
FRONTEND_DIR = SCRIPT_DIR / 'frontend'

os.chdir(FRONTEND_DIR)

# Change working directory to frontend so SimpleHTTPRequestHandler serves files from there
os.chdir(FRONTEND_DIR)

class CloudTapHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format, *args):
        return

    def do_GET(self):
        if self.path == "/data":
            if OUTPUT_FILE.exists():
                with OUTPUT_FILE.open() as f:
                    payload = json.load(f)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"cloudtap_output.json not found")
        else:
            super().do_GET()

# ---------- server loop ----------
def run_server():
    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    with ReusableTCPServer(("0.0.0.0", PORT), CloudTapHandler) as httpd:
        url = f"http://localhost:{PORT}/"
        print(f"Serving CloudTap frontend at {url}")
        try:
            webbrowser.open(url)
        except Exception:
            pass

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server…")
        finally:
            httpd.shutdown()
            httpd.server_close()
            print("Server fully closed.")

# ---------- entry point ----------
if __name__ == "__main__":
    run_server()