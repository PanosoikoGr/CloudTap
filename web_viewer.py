import http.server
import socketserver
import json
import webbrowser
from pathlib import Path

PORT = 8000
OUTPUT_FILE = Path('cloudtap_output.json')

MAIN_PAGE_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CloudTap Results</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    section { margin-bottom: 2em; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ccc; padding: 4px 8px; }
    th { background: #f0f0f0; text-align: left; }
    details { border: 1px solid #ccc; padding: .5em; margin-bottom: 1em; }
    summary { font-weight: bold; cursor: pointer; }
  </style>
</head>
<body>
  <h1>CloudTap Results</h1>
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
      list.forEach(item => {
        const li = document.createElement('li');
        li.textContent = typeof item === 'object' ? JSON.stringify(item) : item;
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
      const div = document.createElement('div');
      div.appendChild(renderSection('Enumerated Permissions', createList(perms.enumerated)));
      div.appendChild(renderSection('Bruteforced Permissions', createList(perms.bruteforced)));
      return div;
    }

    function renderIam(iam) {
      const div = document.createElement('div');
      if (iam.users) div.appendChild(renderSection('Users', createList(iam.users)));
      if (iam.groups) div.appendChild(renderSection('Groups', createList(iam.groups)));
      if (iam.roles) div.appendChild(renderSection('Roles', createList(iam.roles)));
      if (iam.policies) div.appendChild(renderSection('Policies', createList(iam.policies)));
      return div;
    }

    function renderLambda(lam) {
      return renderSection('Lambda Functions', createTableFromObjects(lam.functions));
    }

    function renderBeanstalk(bs) {
      const div = document.createElement('div');
      div.appendChild(renderSection('Applications', createList(bs.applications)));
      div.appendChild(renderSection('Environments', createList(bs.environments)));
      return div;
    }

    function renderEC2(ec2) {
      const container = document.createElement('div');
      Object.entries(ec2.regions || {}).forEach(([region, info]) => {
        const regionDiv = document.createElement('div');
        const details = document.createElement('details');
        const summary = document.createElement('summary');
        summary.textContent = `Region: ${region}`;
        details.appendChild(summary);
        if (info.instances) details.appendChild(renderSection('Instances', createList(info.instances)));
        if (info.volumes) details.appendChild(renderSection('Volumes', createList(info.volumes)));
        if (info.security_groups) details.appendChild(renderSection('Security Groups', createList(info.security_groups)));
        regionDiv.appendChild(details);
        container.appendChild(regionDiv);
      });
      return container;
    }

    function renderSecrets(sm) {
      return renderSection('Secrets Manager', createList(sm.secrets || []));
    }

    function renderS3(s3) {
      return renderSection('S3 Buckets', createList(s3.buckets || []));
    }

    function renderSNS(sns) {
      const div = document.createElement('div');
      div.appendChild(renderSection('Topics', createList(sns.topics)));
      div.appendChild(renderSection('Subscriptions', createList(sns.subscriptions)));
      return div;
    }

    function renderECS(ecs) {
      const div = document.createElement('div');
      div.appendChild(renderSection('Clusters', createList(ecs.clusters || [])));
      if (ecs.services) div.appendChild(renderSection('Services', createList(ecs.services)));
      if (ecs.tasks) div.appendChild(renderSection('Tasks', createList(ecs.tasks)));
      return div;
    }

    function renderPrivilegeEscalation(pe) {
      return renderSection('Privilege Escalation Paths', createList(pe.paths || []));
    }

    fetch('/data')
      .then(resp => resp.json())
      .then(data => {
        const content = document.getElementById('content');
        content.innerHTML = '';
        content.appendChild(renderIdentity(data.identity || {}));
        content.appendChild(renderPermissions(data.permissions || {enumerated: [], bruteforced: []}));
        if (data.iam) content.appendChild(renderSection('IAM', renderIam(data.iam)));
        if (data.ec2) content.appendChild(renderSection('EC2', renderEC2(data.ec2)));
        if (data.lambda) content.appendChild(renderLambda(data.lambda));
        if (data.beanstalk) content.appendChild(renderBeanstalk(data.beanstalk));
        if (data.secrets_manager) content.appendChild(renderSecrets(data.secrets_manager));
        if (data.s3) content.appendChild(renderS3(data.s3));
        if (data.sns) content.appendChild(renderSNS(data.sns));
        if (data.ecs) content.appendChild(renderECS(data.ecs));
        if (data.privilege_escalation) content.appendChild(renderPrivilegeEscalation(data.privilege_escalation));
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
