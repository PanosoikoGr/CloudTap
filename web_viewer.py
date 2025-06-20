import http.server
import socketserver
import json
import webbrowser
from pathlib import Path

PORT = 8000
OUTPUT_FILE = Path('cloudtap_output.json')

MAIN_PAGE_HTML = '''<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>CloudTap Results</title>
<style>
  body { font-family: Arial, sans-serif; margin: 2em; }
  pre { background: #f0f0f0; padding: 1em; overflow-x: auto; }
</style>
</head>
<body>
<h1>CloudTap Results</h1>
<div id="content">Loading...</div>
<script>
  fetch('/data')
    .then(resp => resp.json())
    .then(data => {
      const pre = document.createElement('pre');
      pre.textContent = JSON.stringify(data, null, 2);
      const content = document.getElementById('content');
      content.innerHTML = '';
      content.appendChild(pre);
    })
    .catch(err => {
      document.getElementById('content').textContent = 'Error loading data: ' + err;
    });
</script>
</body>
</html>'''

class CloudTapHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/data':
            if OUTPUT_FILE.exists():
                with OUTPUT_FILE.open() as f:
                    data = json.load(f)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'cloudtap_output.json not found')
        elif self.path in ('/', '/index.html'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(MAIN_PAGE_HTML.encode())
        else:
            super().do_GET()


def run_server():
    with socketserver.TCPServer(('0.0.0.0', PORT), CloudTapHandler) as httpd:
        url = f'http://localhost:{PORT}/'
        print(f'Serving CloudTap results at {url}')
        try:
            webbrowser.open(url)
        except Exception:
            pass
        httpd.serve_forever()


if __name__ == '__main__':
    run_server()
