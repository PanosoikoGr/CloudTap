import http.server
import socketserver
import json
import webbrowser
from pathlib import Path
import logging
import sys

PORT = 8001
OUTPUT_FILE = Path('cloudtap_output.json')

MAIN_PAGE_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="color-scheme" content="light dark">
  <!-- favicon made from a ☁️ emoji -->
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 128 128%22><text y=%22.9em%22 font-size=%22120%22>☁️</text></svg>">
  <title>CloudTap Results</title>
  <style>
    :root{
  --bg: #eaf0f6; --fg:#333;
  --h1:#2c3e50;  --h2:#2980b9;
  --sec-bg:#fff; --shadow:0 4px 10px rgba(0,0,0,.08);
  --th-bg:#f5f8fa; --border:#dcdfe3;
  --tr-even:#f9f9f9; --tr-hover:#eef2f7;
    }
    body.dark{
      --bg:#1e1e20;   --fg:#e7e7e7;
      --h1:#f6f6f6;   --h2:#6cb6ff;
      --sec-bg:#2a2a2d; --shadow:0 4px 10px rgba(0,0,0,.6);
      --th-bg:#2f2f33; --border:#444;
      --tr-even:#262629; --tr-hover:#303035;
    }
    /* ---------- 1B. component styles (unchanged selectors, now using vars) ---------- */
    body{font-family:'Segoe UI',sans-serif;margin:0;padding:20px;
          background:var(--bg);color:var(--fg);}
    h1{color:var(--h1);margin-bottom:30px;margin-left:5%;}
    /* …(everything else the same but switch literal colors → var(--…))… */

    /* ---------- 1C. toggle button ---------- */
    #themeToggle{
      position:fixed;top:18px;right:24px;z-index:999;
      font-size:20px;background:none;border:none;
      cursor:pointer;user-select:none;
    }
    table td,
    table pre { word-break: break-all; white-space: pre-wrap; }
    #content {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      width: 100%;
    }
    section {
      background: var(--sec-bg);
      border-radius: 10px;
      padding: 20px;
      margin: 20px 5% 20px auto;
      width: 90%;
      box-shadow: var(--shadow);
    }
    h2 {
      color: var(--h2);
      margin-top: 0;
    }
    table{
      border-collapse: collapse;
      width:100%;
      margin-top:10px;
      word-break:break-word;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 10px 14px;
      text-align: left;
      vertical-align: top;
    }
    th {
      background: var(--tr-even);
      font-weight: bold;
    }
    tr:hover {
      background:var(--tr-hover);
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
      background:var(--sec-bg);
      box-shadow: 0 2px 6px var(--shadow);
    }
    summary {
      font-weight: bold;
      cursor: pointer;
      color:var(--h1);
    }
    /* Container: invisible strip on the left */
    #toc-container {
      position: fixed;
      top: 100px;                      /* align with header */
      left: 0;
      height: calc(100vh - 100px);
      width: 50px;                     /* enough to cover the handle */
      overflow: visible;               /* let the menu slide out */
      z-index: 1000;
      pointer-events: none;            /* only children receive pointer events */
    }

    /* The vertical “MENU” handle */
    #toc-handle {
      pointer-events: auto;
      position: absolute;
      top: 50%;                        
      left: 15px;                      /* moves the handle 20px into the page */
      transform: translate(-50%, -50%) rotate(-90deg);
      transform-origin: center;
      background: var(--sec-bg);
      padding: 6px 12px;
      border-top-right-radius: 6px;
      border-bottom-right-radius: 6px;
      box-shadow: var(--shadow);
      font-weight: bold;
      cursor: pointer;
      user-select: none;
    }

    /* The sliding menu (initially fully hidden off-screen) */
    #toc {
      pointer-events: auto;
      position: absolute;
      top: 0;
      left: 0;
      width: 200px;
      transform: translateX(-100%);    /* completely off-screen */
      transition: transform 0.3s ease;
      background: var(--sec-bg);
      box-shadow: var(--shadow);
      overflow-y: auto;
      height: 100%;
    }

    /* Slide the menu in when you hover the container (handle or hidden area) */
    #toc-container:hover #toc {
      transform: translateX(0);
    }

    /* TOC list styling */
    #toc .toc-list {
      list-style: none;
      margin: 0;
      padding: 12px;
    }
    #toc .toc-list li + li {
      margin-top: 8px;
    }
    #toc .toc-list a {
      text-decoration: none;
      color: var(--h2);
    }
    #toc .toc-list a:hover {
      text-decoration: underline;
    }

    /* Smooth scroll for anchor links */
    html {
      scroll-behavior: smooth;
    }

      </style>
</head>
<body>
  <h1>☁️ CloudTap Results</h1>
  <!-- TOC container with a vertical MENU handle -->
  <div id="toc-container">
    <div id="toc-handle">MENU</div>
    <nav id="toc">
      <!-- <ul class="toc-list">…generated links…</ul> -->
    </nav>
  </div>
  <button id="themeToggle" aria-label="Toggle dark mode">🌙</button>
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
          const val  = obj[k];

          if (typeof val === 'object' && val !== null) {
            // pretty-print JSON objects
            const pre = document.createElement('pre');
            pre.style.margin = '0';
            pre.textContent = JSON.stringify(val, null, 2); // 2-space indent
            cell.appendChild(pre);
          } else {
            cell.textContent = val;
          }

          /* ← you need this line */
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
      const slug = title.toLowerCase().replace(/\s+/g, '-');
      const section = document.createElement('section');
      section.id = slug;
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

    function createPrivilegeAccordion(paths) {
      if (!Array.isArray(paths) || !paths.length) return document.createTextNode('None');
      const wrap = document.createElement('div');

      paths.forEach(p => {
        const det   = document.createElement('details');
        const sum   = document.createElement('summary');
        sum.textContent = `[#${p.id}] ${p.name} — ${p.impact}`;
        det.appendChild(sum);

        const tbl   = document.createElement('table');
        const body  = document.createElement('tbody');

        const rows = [
          ['Description',          p.description],
          ['Required permissions', (p.required_permissions || []).join(', ') || '—'],
          ['Optional permissions', (p.optional_permissions || []).join(', ') || '—'],
          ['Link',                 p.link ? `<a href="${p.link}" target="_blank">${p.link}</a>` : '—']
        ];

        rows.forEach(([k, v]) => {
          const tr  = document.createElement('tr');
          const th  = document.createElement('th'); th.textContent = k;
          const td  = document.createElement('td'); td.innerHTML   = v;
          tr.appendChild(th); tr.appendChild(td);  body.appendChild(tr);
        });

        tbl.appendChild(body);
        det.appendChild(tbl);
        wrap.appendChild(det);
      });

      return wrap;
    }

      function createBeanstalkAccordion(apps) {
        if (!Array.isArray(apps) || !apps.length) {
          return document.createTextNode('None');
        }

        const wrap = document.createElement('div');

        apps.forEach(app => {
          const det = document.createElement('details');
          const sum = document.createElement('summary');
          sum.textContent = `[${app.region}] ${app.application} — ${app.environments.length} envs`;
          det.appendChild(sum);

          // Top-level app info table
          const info = document.createElement('table');
          info.innerHTML = `
            <tbody>
              <tr><th>Region</th><td>${app.region}</td></tr>
              <tr><th>Environments</th><td>${app.environments.join(', ')}</td></tr>
            </tbody>`;
          det.appendChild(info);

          /* ---- Environment / env-var keys ---- */
          if (app.environments.length) {
            const envTbl = document.createElement('table');
            const tb = document.createElement('tbody');

            const head = document.createElement('tr');
            head.innerHTML = '<th>Environment</th><th>Env-var keys found</th>';
            envTbl.appendChild(head);

            app.environments.forEach(envName => {
              const tr = document.createElement('tr');
              const keys = (app.env_var_keys?.[envName] || []).join(', ') || '—';
              tr.innerHTML = `<td>${envName}</td><td>${keys}</td>`;
              tb.appendChild(tr);
            });

            envTbl.appendChild(tb);
            det.appendChild(envTbl);
          }

          wrap.appendChild(det);
        });

        return wrap;
      }

      function createSnsAccordion(topics, subs) {
        if (!Array.isArray(topics) || !topics.length) {
          return document.createTextNode('None');
        }
        const wrap = document.createElement('div');

        topics.forEach(t => {
          const det  = document.createElement('details');
          const sum  = document.createElement('summary');
          sum.textContent =
            `[${t.region}] ${t.name} — ${t.subscription_count} subscription`
            + (t.subscription_count === 1 ? '' : 's');
          det.appendChild(sum);

          /* topic info */
          const info = document.createElement('table');
          info.innerHTML = `
            <tbody>
              <tr><th>Region</th><td>${t.region}</td></tr>
              <tr><th>ARN</th><td style="word-break:break-all">${t.arn}</td></tr>
              <tr><th>Subscriptions</th><td>${t.subscription_count}</td></tr>
            </tbody>`;
          det.appendChild(info);

          /* matching subscriptions */
          const relSubs = (subs || []).filter(s => s.topic_arn === t.arn);
          if (relSubs.length) {
            const subTbl = createTableFromObjects(relSubs);
            det.appendChild(subTbl);
          }

          wrap.appendChild(det);
        });

        return wrap;
      }

      function createS3Accordion(buckets) {
        if (!Array.isArray(buckets) || !buckets.length) {
          return document.createTextNode('None');
        }
        const wrap = document.createElement('div');

        buckets.forEach(b => {
          const det = document.createElement('details');
          const sum = document.createElement('summary');
          sum.textContent =
            `[${b.region}] ${b.name} — ${b.objects.length} object`
            + (b.objects.length === 1 ? '' : 's');
          det.appendChild(sum);

          /* bucket info table */
          const info = document.createElement('table');
          info.innerHTML = `
            <tbody>
              <tr><th>Region</th><td>${b.region}</td></tr>
              <tr><th>Objects</th><td>${b.objects.length}</td></tr>
            </tbody>`;
          det.appendChild(info);

          /* list of keys (in two columns if long) */
          if (b.objects.length) {
            const ul = document.createElement('ul');
            ul.style.columns = '2 300px';      /* two columns, min 300 px each */
            ul.style.paddingLeft = '20px';

            b.objects.forEach(k => {
              const li = document.createElement('li');
              li.textContent = k;
              ul.appendChild(li);
            });
            det.appendChild(ul);
          }

          wrap.appendChild(det);
        });

        return wrap;
      }
    function makeEc2RegionTable(regionObj) {
      if (!regionObj || Object.keys(regionObj).length === 0) {
        return document.createTextNode('None');
      }
      /* flatten { "us-east-1": {…}, "eu-west-1": {…} } -> [{region:"us-east-1", …}, …] */
      const rows = Object.entries(regionObj).map(([region, stats]) => ({
        region,
        ...stats
      }));
      return createTableFromObjects(rows);
      }

        function createEc2Accordion(instances) {
      if (!Array.isArray(instances) || !instances.length) {
        return document.createTextNode('None');
      }

      const wrap = document.createElement('div');

      /* sort by region then instance-id for a stable order */
      instances
        .slice()
        .sort((a, b) => a.region.localeCompare(b.region) ||
                        a.id.localeCompare(b.id))
        .forEach(inst => {
          const det = document.createElement('details');
          const sum = document.createElement('summary');

          const badge = inst.state === 'running'
            ? '🟢'
            : inst.state === 'stopped'
              ? '⏹️'
              : '⚪';

          sum.textContent = `[${inst.region}] ${inst.id} — ${inst.type} ${badge}`;
          det.appendChild(sum);

          /* — basic facts table — */
          const tbl = document.createElement('table');
          tbl.innerHTML = `
            <tbody>
              <tr><th>State</th><td>${inst.state}</td></tr>
              <tr><th>AMI</th><td>${inst.ami}</td></tr>
              <tr><th>Public IP</th><td>${inst.public_ip || '—'}</td></tr>
              <tr><th>Private IP</th><td>${inst.private_ip || '—'}</td></tr>
              <tr><th>Key pair</th><td>${inst.key_pair || '—'}</td></tr>
              <tr><th>IAM profile</th><td style="word-break:break-all">
                ${inst.iam_profile || '—'}
              </td></tr>
            </tbody>`;
          det.appendChild(tbl);

          /* — security groups — */
          if (inst.security_groups?.length) {
            const sgUl = createList(inst.security_groups);
            det.appendChild(renderSection('Security Groups', sgUl));
          }

          /* — attached volumes — */
          if (inst.volumes?.length) {
            const volUl = createList(inst.volumes);
            det.appendChild(renderSection('EBS Volumes', volUl));
          }

          wrap.appendChild(det);
        });

      return wrap;
    }
    /* ------------- IAM user accordion ------------- */
    function createIamAccordion(users) {
      if (!Array.isArray(users) || !users.length) {
        return document.createTextNode('None');
      }

      const wrap = document.createElement('div');

      users.forEach(u => {
        const det = document.createElement('details');
        const sum = document.createElement('summary');

        const ap = u.attached_policies?.length || 0,
              ip = u.inline_policies?.length   || 0,
              gp = u.groups?.length            || 0;

        sum.textContent = `${u.username} — ${ap} AP / ${ip} IP / ${gp} groups`;
        det.appendChild(sum);

        /* basic counts table */
        const info = document.createElement('table');
        info.innerHTML = `
          <tbody>
            <tr><th>Attached policies</th><td>${ap}</td></tr>
            <tr><th>Inline policies</th><td>${ip}</td></tr>
            <tr><th>Groups</th><td>${gp}</td></tr>
          </tbody>`;
        det.appendChild(info);

        /* attached managed policies */
        if (ap) {
          const apTbl = createTableFromObjects(u.attached_policies);
          det.appendChild(renderSection('Attached Policies', apTbl));
        }

        /* inline user policies */
        if (ip) {
          const ipTbl = createTableFromObjects(u.inline_policies);
          det.appendChild(renderSection('Inline Policies', ipTbl));
        }

        /* groups with their policies */
        if (gp) {
          u.groups.forEach(g => {
            const gDet  = document.createElement('details');
            const gSum  = document.createElement('summary');
            gSum.textContent =
              `Group: ${g.name} — ${g.attached_policies.length} AP / ${g.inline_policies.length} IP`;
            gDet.appendChild(gSum);

            const gTbl = document.createElement('table');
            gTbl.innerHTML = `
              <tbody>
                <tr><th>ARN</th><td style="word-break:break-all">${g.arn}</td></tr>
              </tbody>`;
            gDet.appendChild(gTbl);

            if (g.attached_policies.length) {
              gDet.appendChild(
                renderSection('Group Attached Policies',
                              createTableFromObjects(g.attached_policies))
              );
            }
            if (g.inline_policies.length) {
              gDet.appendChild(
                renderSection('Group Inline Policies',
                              createTableFromObjects(g.inline_policies))
              );
            }

            det.appendChild(gDet);
          });
        }

        wrap.appendChild(det);
      });

      return wrap;
    }

    function hasRoleData(roles) {
      return Object.values(roles).some(value => {
        if (Array.isArray(value)) {
          return value.length > 0;
        }
        if (typeof value === 'object' && value !== null) {
          return Object.keys(value).length > 0;
        }
        return Boolean(value); // fallback for primitives (rare)
      });
    }

    /* ------------- ROLES accordion ------------- */
    function createRolesAccordion(rolesObj) {
      if (!rolesObj || Object.keys(rolesObj).length === 0) {
        return document.createTextNode('None');
      }

      const wrap = document.createElement('div');

      /* --- 1. “All roles” table --- */
      if (Array.isArray(rolesObj.all) && rolesObj.all.length) {
        wrap.appendChild(
          renderSection('All Enumerated Roles',
                        createTableFromObjects(rolesObj.all))
        );
      }

      /* --- 2. Matching roles (trust-policy hits) --- */
      if (rolesObj.matching?.length) {
        wrap.appendChild(
          renderSection('Trust-Policy Matches',
                        createList(rolesObj.matching))
        );
      }

      /* --- 3. Attempted assumptions --- */
      if (rolesObj.attempted?.length) {
        wrap.appendChild(
          renderSection('AssumeRole Attempts',
                        createList(rolesObj.attempted))
        );
      }

      /* --- 4. Successful assumptions (rich detail) --- */
      if (rolesObj.successful?.length) {
        const detWrap = document.createElement('div');

        rolesObj.successful.forEach(s => {
          const det = document.createElement('details');
          const sum = document.createElement('summary');
          sum.textContent = `${s.role_name} — SUCCESS`;
          det.appendChild(sum);

          /* basic info table */
          const info = document.createElement('table');
          info.innerHTML = `
            <tbody>
              <tr><th>Role ARN</th><td style="word-break:break-all">${s.role_arn}</td></tr>
              <tr><th>Expiration</th><td>${s.credentials?.Expiration || '—'}</td></tr>
            </tbody>`;
          det.appendChild(info);

          /* credentials */
          if (s.credentials) {
            const credTbl = createTableFromObjects([s.credentials]);
            det.appendChild(renderSection('Temp Credentials', credTbl));
          }

          /* managed policies */
          if (Array.isArray(s.managed_policies) && s.managed_policies.length) {
            det.appendChild(
              renderSection('Managed Policies',
                            createTableFromObjects(s.managed_policies))
            );
          }

          /* inline policies */
          if (Array.isArray(s.inline_policies) && s.inline_policies.length) {
            det.appendChild(
              renderSection('Inline Policies',
                            createTableFromObjects(s.inline_policies))
            );
          }

          /* permissions list */
          if (s.permissions?.length) {
            det.appendChild(
              renderSection('Allowed Actions',
                            createList(s.permissions))
            );
          }

          detWrap.appendChild(det);
        });

        wrap.appendChild(renderSection('Successfully Assumed Roles', detWrap));
      }

      return wrap;
    }
    (function(){
      const BODY = document.body;
      const BTN  = document.getElementById('themeToggle');

      // apply saved pref or media default
      const saved = localStorage.getItem('ct-theme');
      if(saved ? saved==='dark' : window.matchMedia('(prefers-color-scheme: dark)').matches){
        BODY.classList.add('dark');
        BTN.textContent = '☀️';
      }

      BTN.addEventListener('click', () =>{
        const dark = BODY.classList.toggle('dark');
        BTN.textContent = dark ? '☀️' : '🌙';
        localStorage.setItem('ct-theme', dark ? 'dark' : 'light');
      });
    })();
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
        if (data.iam?.users?.length) {
          content.appendChild(
            renderSection('IAM → Users',
                          createIamAccordion(data.iam.users))
          );
        }
        // ROLES
        if (data.roles && hasRoleData(data.roles)) {
          content.appendChild(
            renderSection('Roles (Discovery & Assumption)',
                          createRolesAccordion(data.roles))
          );
        }

        // EC2 Region Summary
        if (data.ec2?.regions && Object.keys(data.ec2.regions).length) {
          content.appendChild(
            renderSection('EC2 Regions',
                          makeEc2RegionTable(data.ec2.regions))
          );
        }

        if (data.ec2?.instances?.length) {
          content.appendChild(
            renderSection('EC2 Instances',
                          createEc2Accordion(data.ec2.instances))
          );
        }

        // Lambda
        if (data.lambda?.functions?.length) {
          content.appendChild(renderSection(
            'Lambda Functions',
            createTableFromObjects(data.lambda.functions)
          ));
        }

        // Beanstalk
        if (data.beanstalk?.applications?.length) {
          content.appendChild(
            renderSection('Beanstalk Applications',
                          createBeanstalkAccordion(data.beanstalk.applications))
          );
        }

        if (data.beanstalk?.environments?.length) {
          content.appendChild(
            renderSection('Beanstalk Environments (flat list)',
                          createList(data.beanstalk.environments))
          );
        }

        // Secrets Manager
        if (data.secrets_manager?.secrets?.length) {
          content.appendChild(renderSection(
            'Secrets Manager',
            createTableFromObjects(data.secrets_manager.secrets)
          ));
        }

        // S3
        if (data.s3?.buckets?.length) {
          content.appendChild(
            renderSection(
              'S3 Buckets',
              createS3Accordion(data.s3.buckets)
            )
          );
        }

        // SNS
        if (data.sns?.topics?.length) {
          content.appendChild(
            renderSection(
              'SNS Topics',
              createSnsAccordion(data.sns.topics, data.sns.subscriptions || [])
            )
          );
        }

        // ECS
        if (data.ecs?.clusters?.length) {
          content.appendChild(
            renderSection('ECS Clusters',
                          createTableFromObjects(data.ecs.clusters))
          );
        }

        //Priv Esc
        if (data.privilege_escalation?.paths?.length) {
          content.appendChild(
            renderSection('Privilege Escalation Paths',
                          createPrivilegeAccordion(data.privilege_escalation.paths))
          );
        }

        // after you populate `content.innerHTML = ''` and append all sections...
        const toc = document.getElementById('toc');
        const headings = document.querySelectorAll('#content section h2');
        if (headings.length) {
          const ul = document.createElement('ul');
          ul.className = 'toc-list';
          headings.forEach(h2 => {
            const li = document.createElement('li');
            const a  = document.createElement('a');
            const title = h2.textContent;
            const slug  = h2.parentElement.id;
            a.textContent = title;
            a.href = `#${slug}`;
            li.appendChild(a);
            ul.appendChild(li);
          });
          toc.appendChild(ul);
        }

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
    # allow_reuse_address lets the OS re-allocate the port right away
    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    with ReusableTCPServer(("0.0.0.0", PORT), CloudTapHandler) as httpd:
        url = f"http://localhost:{PORT}/"
        print(f"Serving CloudTap results at {url}")
        try:
            webbrowser.open(url)
        except Exception:
            pass                  # opening the browser is best-effort

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server…")
        finally:
            # ensure the loop stops and the socket is closed
            httpd.shutdown()
            httpd.server_close()
            print("Server fully closed.")

# ---------- entry point ----------
if __name__ == "__main__":
    run_server()