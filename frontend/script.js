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

function slugify(str) {
    return str.toLowerCase()
              .replace(/[^a-z0-9]+/g, '-')
              .replace(/^-|-$/g, '');
}

function renderSection(title, content) {
    const slug = slugify(title);
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

function renderOverview(data) {
    const items = [
        ['IAM Users', data.iam?.users?.length || 0],
        ['Enumerated Permissions', data.permissions?.enumerated?.length || 0],
        ['Bruteforced Permissions', data.permissions?.bruteforced?.length || 0],
        ['Roles', data.roles?.all?.length || 0],
        ['Successful Assumed Roles', data.roles?.successful?.length || 0],
        ['Lambda Functions', data.lambda?.functions?.length || 0],
        ['EC2 Instances', data.ec2?.instances?.length || 0],
        ['S3 Buckets', data.s3?.buckets?.length || 0]
    ];
    const tableData = items.map(([k, v]) => ({ Item: k, Count: v }));
    return renderSection('Overview', createTableFromObjects(tableData));
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
        const menu    = document.getElementById('menu');
        const content = document.getElementById('content');
        const sections = [];

        function add(title, el) {
            if (!el) return;
            const id = slugify(title);
            el.id = id;
            sections.push({ id, title, el });
        }

        add('Overview', renderOverview(data));
        add('Identity', renderIdentity(data.identity || {}));

        const permsSection = renderPermissions(data.permissions || {});
        if (permsSection) add('Permissions', permsSection);

        if (data.iam?.users?.length) {
            add('IAM Users',
                renderSection('IAM → Users', createIamAccordion(data.iam.users)));
        }

        if (data.roles && hasRoleData(data.roles)) {
            add('Roles',
                renderSection('Roles (Discovery & Assumption)',
                              createRolesAccordion(data.roles)));
        }

        if (data.ec2?.regions && Object.keys(data.ec2.regions).length) {
            add('EC2 Regions',
                renderSection('EC2 Regions', makeEc2RegionTable(data.ec2.regions)));
        }

        if (data.ec2?.instances?.length) {
            add('EC2 Instances',
                renderSection('EC2 Instances', createEc2Accordion(data.ec2.instances)));
        }

        if (data.lambda?.functions?.length) {
            add('Lambda Functions',
                renderSection('Lambda Functions',
                              createTableFromObjects(data.lambda.functions)));
        }

        if (data.beanstalk?.applications?.length) {
            add('Beanstalk Applications',
                renderSection('Beanstalk Applications',
                              createBeanstalkAccordion(data.beanstalk.applications)));
        }

        if (data.beanstalk?.environments?.length) {
            add('Beanstalk Environments',
                renderSection('Beanstalk Environments (flat list)',
                              createList(data.beanstalk.environments)));
        }

        if (data.secrets_manager?.secrets?.length) {
            add('Secrets Manager',
                renderSection('Secrets Manager',
                              createTableFromObjects(data.secrets_manager.secrets)));
        }

        if (data.s3?.buckets?.length) {
            add('S3 Buckets',
                renderSection('S3 Buckets',
                              createS3Accordion(data.s3.buckets)));
        }

        if (data.sns?.topics?.length) {
            add('SNS Topics',
                renderSection('SNS Topics',
                              createSnsAccordion(data.sns.topics, data.sns.subscriptions || [])));
        }

        if (data.ecs?.clusters?.length) {
            add('ECS Clusters',
                renderSection('ECS Clusters', createTableFromObjects(data.ecs.clusters)));
        }

        if (data.privilege_escalation?.paths?.length) {
            add('Privilege Escalation',
                renderSection('Privilege Escalation Paths',
                              createPrivilegeAccordion(data.privilege_escalation.paths)));
        }

        function showSection(id) {
            const sec = sections.find(s => s.id === id);
            if (!sec) return;
            content.innerHTML = '';
            content.appendChild(sec.el);
            document.querySelectorAll('#menu a').forEach(a => {
                a.classList.toggle('active', a.dataset.target === id);
            });
        }

        sections.forEach(sec => {
            const li = document.createElement('li');
            const a  = document.createElement('a');
            a.textContent = sec.title;
            a.href = '#';
            a.dataset.target = sec.id;
            a.addEventListener('click', e => {
                e.preventDefault();
                showSection(sec.id);
            });
            li.appendChild(a);
            menu.appendChild(li);
        });

        showSection('overview');
    })
    .catch(err => {
        document.getElementById('content').textContent = 'Error loading data: ' + err;
    });