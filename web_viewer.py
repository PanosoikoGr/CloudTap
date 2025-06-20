import http.server
import socketserver
import json
import webbrowser
from pathlib import Path
import logging
import sys

PORT = 8000
OUTPUT_FILE = Path('cloudtap_output.json')

MAIN_PAGE_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CloudTap Results</title>
  <style>
    body {
      font-family: 'Segoe UI', sans-serif;
      margin: 0;
      padding: 20px;
      background-color: #eaf0f6;
      color: #333;
    }
    h1 {
      color: #2c3e50;
      margin-bottom: 30px;
      margin-left: 5%;
    }
    #content {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      width: 100%;
    }
    section {
      background: #fff;
      border-radius: 10px;
      padding: 20px;
      margin: 20px 5% 20px auto;
      width: 90%;
      box-shadow: 0 4px 10px rgba(0,0,0,0.08);
    }
    h2 {
      color: #2980b9;
      margin-top: 0;
    }
    table {
      border-collapse: collapse;
      width: 100%;
      margin-top: 10px;
      word-break: break-word;
    }
    th, td {
      border: 1px solid #dcdfe3;
      padding: 10px 14px;
      text-align: left;
      vertical-align: top;
    }
    th {
      background-color: #f5f8fa;
      font-weight: bold;
    }
    tr:nth-child(even) {
      background-color: #f9f9f9;
    }
    tr:hover {
      background-color: #eef2f7;
    }
    .permissions-wrapper {
      display: flex;
      justify-content: center;
      gap: 40px;
      margin-bottom: 20px;
    }
    .permission-section {
      flex: 0 0 45%;
    }
    .permission-list {
      columns: 2;
      column-gap: 20px;
      list-style: disc inside;
      padding: 0;
      margin: 0;
    }
    .permission-list li {
      break-inside: avoid;
      padding: 4px 0;
    }
    details {
      border: 1px solid #ccc;
      border-radius: 6px;
      padding: .75em 1em;
      margin: 20px 5% 20px auto;
      width: 90%;
      background-color: #fff;
      box-shadow: 0 2px 6px rgba(0,0,0,0.05);
    }
    summary {
      font-weight: bold;
      cursor: pointer;
      color: #2c3e50;
    }
  </style>
</head>
<body>
  <h1>☁️ CloudTap Results</h1>
  <div id="content">Loading...</div>
  <script>
    function createTableFromObjects(list) {
      if (!Array.isArray(list) || !list.length) {
        const span = document.createElement('span');
        span.textContent = 'None';
        return span;
      }
      const table = document.createElement('table');
      const thead = document.createElement('thead');
      const keys = Object.keys(list[0]);
      const headerRow = document.createElement('tr');
      keys.forEach(k => {
        const th = document.createElement('th');
        th.textContent = k;
        headerRow.appendChild(th);
      });
      thead.appendChild(headerRow);
      table.appendChild(thead);
      const tbody = document.createElement('tbody');
      list.forEach(obj => {
        const row = document.createElement('tr');
        keys.forEach(k => {
          const cell = document.createElement('td');
          const val = obj[k];
          cell.textContent = typeof val === 'object' ? JSON.stringify(val) : val;
          row.appendChild(cell);
        });
        tbody.appendChild(row);
      });
      table.appendChild(tbody);
      return table;
    }

    function createList(list) {
      const ul = document.createElement('ul');
      ul.className = 'permission-list';
      list.forEach(item => {
        const li = document.createElement('li');
        li.textContent = typeof item === 'object'
          ? JSON.stringify(item)
          : item;
        ul.appendChild(li);
      });
      return ul;
    }

    function renderSection(title, content) {
      const section = document.createElement('section');
      const h2 = document.createElement('h2');
      h2.textContent = title;
      section.appendChild(h2);
      section.appendChild(content);
      return section;
    }

    function renderIdentity(identity) {
      return renderSection('Identity', createTableFromObjects([identity]));
    }

    function renderPermissions(perms) {
      // if both empty, skip
      if ((!perms.enumerated || !perms.enumerated.length) &&
          (!perms.bruteforced || !perms.bruteforced.length)) {
        return null;
      }
      const wrapper = document.createElement('div');
      wrapper.className = 'permissions-wrapper';

      const enumSec = document.createElement('div');
      enumSec.className = 'permission-section';
      enumSec.appendChild(renderSection('Enumerated Permissions',
                                        createList(perms.enumerated || [])));

      const brutSec = document.createElement('div');
      brutSec.className = 'permission-section';
      brutSec.appendChild(renderSection('Bruteforced Permissions',
                                        createList(perms.bruteforced || [])));

      wrapper.appendChild(enumSec);
      wrapper.appendChild(brutSec);
      return renderSection('Permissions', wrapper);
    }

    function renderListSection(title, list) {
      if (!Array.isArray(list) || !list.length) return null;
      return renderSection(title, createList(list));
    }

    function renderDetailsSection(title, obj) {
      if (!obj || Object.keys(obj).length === 0) return null;
      const div = document.createElement('div');
      Object.entries(obj).forEach(([key, val]) => {
        if (!Array.isArray(val) || !val.length) return;
        div.appendChild(renderSection(key.charAt(0).toUpperCase() + key.slice(1),
                                     createList(val)));
      });
      return div.children.length ? renderSection(title, div) : null;
    }

    fetch('/data')
      .then(resp => resp.json())
      .then(data => {
        const content = document.getElementById('content');
        content.innerHTML = '';

        // Identity
        content.appendChild(renderIdentity(data.identity || {}));

        // Permissions
        const permsSection = renderPermissions(data.permissions || {});
        if (permsSection) content.appendChild(permsSection);

        // IAM (users/groups/roles/policies)
        const iamSec = renderDetailsSection('IAM', data.iam || {});
        if (iamSec) content.appendChild(iamSec);

        // EC2 Regions
        const ec2Sec = renderDetailsSection('EC2', data.ec2?.regions || {});
        if (ec2Sec) content.appendChild(ec2Sec);

        // Lambda
        if (data.lambda?.functions?.length) {
          content.appendChild(renderSection(
            'Lambda Functions',
            createTableFromObjects(data.lambda.functions)
          ));
        }

        // Beanstalk
        const bsSec = renderListSection('Beanstalk Applications', data.beanstalk?.applications);
        const bsEnv = renderListSection('Beanstalk Environments', data.beanstalk?.environments);
        if (bsSec) content.appendChild(bsSec);
        if (bsEnv) content.appendChild(bsEnv);

        // Secrets Manager
        if (data.secrets_manager?.secrets?.length) {
          content.appendChild(renderSection(
            'Secrets Manager',
            createTableFromObjects(data.secrets_manager.secrets)
          ));
        }

        // S3
        const s3Sec = renderListSection('S3 Buckets', data.s3?.buckets);
        if (s3Sec) content.appendChild(s3Sec);

        // SNS
        const snsTop = renderListSection('SNS Topics', data.sns?.topics);
        const snsSub = renderListSection('SNS Subscriptions', data.sns?.subscriptions);
        if (snsTop) content.appendChild(snsTop);
        if (snsSub) content.appendChild(snsSub);

        // ECS
        const ecsSec = renderListSection('ECS Clusters', data.ecs?.clusters);
        if (ecsSec) content.appendChild(ecsSec);

        // Privilege Escalation Paths
        const peSec = renderListSection('Privilege Escalation Paths',
                                        data.privilege_escalation?.paths);
        if (peSec) content.appendChild(peSec);
      })
      .catch(err => {
        document.getElementById('content')
                .textContent = 'Error loading data: ' + err;
      });
  </script>
</body>
</html>'''


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
        elif self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(MAIN_PAGE_HTML.encode())
        else:
            super().do_GET()

# ---------- server loop ----------
def run_server():
    with socketserver.TCPServer(("0.0.0.0", PORT), CloudTapHandler) as httpd:
        url = f"http://localhost:{PORT}/"
        print(f"Serving CloudTap results at {url}")
        try:
            webbrowser.open(url)
        except Exception:
            pass                  # opening the browser is best-effort

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")

# ---------- entry point ----------
if __name__ == "__main__":
    run_server()