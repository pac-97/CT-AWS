const statusPill = document.getElementById('status-pill');
const pageId = document.body.dataset.page || '';

function setStatus(text, ok = true) {
  if (!statusPill) return;
  statusPill.textContent = text;
  statusPill.style.color = ok ? '#13a24b' : '#b33b2e';
  statusPill.style.borderColor = ok ? 'rgba(19,162,75,.26)' : 'rgba(179,59,46,.35)';
  statusPill.style.background = ok ? 'rgba(19,162,75,.12)' : 'rgba(179,59,46,.12)';
}

function initModuleNavigation() {
  const navs = document.querySelectorAll('.module-nav');
  navs.forEach((nav) => {
    const buttons = Array.from(nav.querySelectorAll('button[data-target]'));
    const defaultTarget = nav.dataset.default || (buttons[0] ? buttons[0].dataset.target : null);

    const activate = (targetId) => {
      buttons.forEach((btn) => btn.classList.toggle('active', btn.dataset.target === targetId));
      const panels = document.querySelectorAll('.module-panel');
      panels.forEach((panel) => panel.classList.toggle('hidden', panel.id !== targetId));
    };

    buttons.forEach((btn) => btn.addEventListener('click', () => activate(btn.dataset.target)));
    if (defaultTarget) activate(defaultTarget);
  });
}

async function jsonFetch(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function toOptions(select, items, valueKey, labelBuilder) {
  if (!select) return;
  select.innerHTML = '';
  items.forEach((item) => {
    const opt = document.createElement('option');
    opt.value = item[valueKey];
    opt.textContent = labelBuilder(item);
    select.appendChild(opt);
  });
}

function selectedValues(selectEl) {
  if (!selectEl) return [];
  return Array.from(selectEl.selectedOptions).map((o) => o.value);
}

function uniqueLines(text) {
  const items = text
    .split(/\r?\n|,/) 
    .map((x) => x.trim())
    .filter(Boolean);
  return [...new Set(items)];
}

function makeLogger() {
  const box = document.getElementById('log-box');
  return (message, data) => {
    if (!box) return;
    const now = new Date().toISOString();
    const line = `[${now}] ${message}`;
    box.textContent = `${line}${data ? `\n${JSON.stringify(data, null, 2)}` : ''}\n\n${box.textContent}`;
  };
}

async function initIamIdentityCenterPage() {
  const log = makeLogger();
  let BOOTSTRAP = { permission_sets: [], accounts: [], groups: [], users: [] };

  const renderPermissionTable = (permissionSets) => {
    const tbody = document.querySelector('#perm-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    permissionSets.forEach((p) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${p.name}</td>
        <td>${p.description || ''}</td>
        <td>${p.session_duration || ''}</td>
        <td><code>${p.arn}</code></td>
      `;
      tbody.appendChild(tr);
    });
  };

  const refreshPrincipalOptions = (type) => {
    const principalSelect = document.getElementById('principal-id');
    if (!principalSelect) return;
    if (type === 'USER') {
      toOptions(principalSelect, BOOTSTRAP.users, 'id', (u) => `${u.display_name || u.username} (${u.email || 'no-email'})`);
    } else {
      toOptions(principalSelect, BOOTSTRAP.groups, 'id', (g) => `${g.name} (${g.id})`);
    }
  };

  const loadManagedPolicyCatalog = async () => {
    const catalog = document.getElementById('policy-catalog');
    if (!catalog) return;
    const data = await jsonFetch('/api/iam/managed-policies?scope=All&limit=1000');
    toOptions(catalog, data.items || [], 'arn', (p) => `${p.name} (${p.scope})`);
    log('Managed policy catalog loaded', { count: (data.items || []).length });
  };

  const bootstrap = async () => {
    setStatus('Loading AWS data...', true);
    const data = await jsonFetch('/api/bootstrap');
    BOOTSTRAP = data;

    const meta = document.getElementById('instance-meta');
    if (meta) meta.textContent = `Region: ${data.instance.region} | Identity Store: ${data.instance.identity_store_id}`;

    toOptions(document.getElementById('provision-accounts'), data.accounts, 'id', (a) => `${a.name} (${a.id})`);
    toOptions(document.getElementById('assign-account'), data.accounts, 'id', (a) => `${a.name} (${a.id})`);
    toOptions(document.getElementById('assign-perm'), data.permission_sets, 'arn', (p) => `${p.name} (${p.arn.split('/').slice(-1)[0] || 'perm'})`);

    renderPermissionTable(data.permission_sets);
    refreshPrincipalOptions('GROUP');
    await loadManagedPolicyCatalog();
    setStatus('Connected to AWS', true);
    log('IAM workspace loaded', {
      accounts: data.accounts.length,
      permissionSets: data.permission_sets.length,
      groups: data.groups.length,
      users: data.users.length,
    });
  };

  const parseDesiredState = () => {
    const desiredEl = document.getElementById('desired-state');
    if (!desiredEl) throw new Error('Desired state field not found');
    const text = desiredEl.value.trim() || '{"permission_sets": []}';
    return JSON.parse(text);
  };

  const setDesiredDefault = () => {
    const desiredEl = document.getElementById('desired-state');
    if (!desiredEl || desiredEl.value.trim()) return;
    desiredEl.value = JSON.stringify({
      permission_sets: [{
        name: 'SecurityAudit-Prod',
        description: 'Read-only security audit access',
        session_duration: 'PT4H',
        managed_policy_arns: ['arn:aws:iam::aws:policy/SecurityAudit'],
        inline_policy: null,
        provision_account_ids: [],
      }],
    }, null, 2);
  };

  const wireEvents = () => {
    const addPoliciesBtn = document.getElementById('add-selected-policies');
    if (addPoliciesBtn) {
      addPoliciesBtn.addEventListener('click', () => {
        const catalog = document.getElementById('policy-catalog');
        const textarea = document.querySelector('textarea[name="managed_policy_arns"]');
        if (!catalog || !textarea) return;
        const selected = selectedValues(catalog);
        const merged = [...uniqueLines(textarea.value), ...selected];
        textarea.value = [...new Set(merged)].join('\n');
      });
    }

    const permissionForm = document.getElementById('permission-form');
    if (permissionForm) {
      permissionForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const payload = {
          name: form.name.value,
          description: form.description.value,
          session_duration: form.session_duration.value,
          managed_policy_arns: uniqueLines(form.managed_policy_arns.value),
          inline_policy: form.inline_policy.value,
          provision_account_ids: selectedValues(document.getElementById('provision-accounts')),
        };

        try {
          setStatus('Applying change to AWS...', true);
          const result = await jsonFetch('/api/permission-sets/upsert', { method: 'POST', body: JSON.stringify(payload) });
          log('Permission set upsert complete', result);
          await bootstrap();
          setStatus('Change pushed to AWS', true);
        } catch (err) {
          setStatus('Update failed', false);
          log(`Permission update failed: ${err.message}`);
        }
      });
    }

    const assignmentForm = document.getElementById('assignment-form');
    if (assignmentForm) {
      assignmentForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const payload = {
          account_id: form.account_id.value,
          permission_set_arn: form.permission_set_arn.value,
          principal_type: form.principal_type.value,
          principal_id: form.principal_id.value,
        };

        try {
          setStatus('Creating assignment...', true);
          const result = await jsonFetch('/api/assignments', { method: 'POST', body: JSON.stringify(payload) });
          log('Account assignment request submitted', result);
          setStatus('Assignment submitted', true);
        } catch (err) {
          setStatus('Assignment failed', false);
          log(`Assignment failed: ${err.message}`);
        }
      });
    }

    const principalType = document.getElementById('principal-type');
    if (principalType) principalType.addEventListener('change', (e) => refreshPrincipalOptions(e.target.value));

    const planBtn = document.getElementById('plan-btn');
    if (planBtn) {
      planBtn.addEventListener('click', async () => {
        try {
          setStatus('Generating drift plan...', true);
          const result = await jsonFetch('/api/drift/plan', { method: 'POST', body: JSON.stringify({ desired_state: parseDesiredState() }) });
          document.getElementById('plan-output').textContent = JSON.stringify(result, null, 2);
          log('Drift plan generated', result.summary || result);
          setStatus('Plan ready', true);
        } catch (err) {
          setStatus('Plan failed', false);
          log(`Plan failed: ${err.message}`);
        }
      });
    }

    const applyBtn = document.getElementById('apply-btn');
    if (applyBtn) {
      applyBtn.addEventListener('click', async () => {
        try {
          setStatus('Applying plan...', true);
          const result = await jsonFetch('/api/drift/apply', { method: 'POST', body: JSON.stringify({ desired_state: parseDesiredState() }) });
          document.getElementById('plan-output').textContent = JSON.stringify(result, null, 2);
          log('Drift apply complete', result.plan_summary || result);
          await bootstrap();
          setStatus('Plan applied', true);
        } catch (err) {
          setStatus('Apply failed', false);
          log(`Apply failed: ${err.message}`);
        }
      });
    }
  };

  setDesiredDefault();
  wireEvents();
  try {
    await bootstrap();
  } catch (err) {
    setStatus('AWS connection failed', false);
    log(`Bootstrap error: ${err.message}`);
  }
}

async function initStateImportPage() {
  const output = document.getElementById('state-output');
  const importBtn = document.getElementById('import-state-btn');
  const copyBtn = document.getElementById('copy-state-btn');
  const modulesSelect = document.getElementById('import-modules');
  const auditTbody = document.querySelector('#audit-table tbody');

  const loadModuleOptions = async () => {
    if (!modulesSelect) return;
    const data = await jsonFetch('/api/state/import/modules');
    toOptions(modulesSelect, (data.modules || []).map((m) => ({ value: m })), 'value', (m) => m.value);
    Array.from(modulesSelect.options).forEach((o) => (o.selected = true));
  };

  const loadAudit = async () => {
    if (!auditTbody) return;
    const data = await jsonFetch('/api/audit?limit=100');
    auditTbody.innerHTML = '';
    (data.events || []).forEach((e) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${e.timestamp || ''}</td>
        <td>${e.actor_username || ''}</td>
        <td>${e.action || ''}</td>
        <td>${e.status || ''}</td>
        <td>${e.target || ''}</td>
        <td>${e.error_text || ''}</td>
      `;
      auditTbody.appendChild(tr);
    });
  };

  if (importBtn) {
    importBtn.addEventListener('click', async () => {
      try {
        setStatus('Importing selected AWS modules...', true);
        const modules = selectedValues(modulesSelect);
        const query = modules.length ? `?modules=${encodeURIComponent(modules.join(','))}` : '';
        const data = await jsonFetch(`/api/state/import${query}`);
        if (output) output.textContent = JSON.stringify(data.state, null, 2);
        await loadAudit();
        setStatus('State import complete', true);
      } catch (err) {
        setStatus('State import failed', false);
        if (output) output.textContent = err.message;
      }
    });
  }

  if (copyBtn) {
    copyBtn.addEventListener('click', async () => {
      if (!output || !output.textContent) return;
      try {
        await navigator.clipboard.writeText(output.textContent);
        setStatus('State JSON copied', true);
      } catch {
        setStatus('Copy failed', false);
      }
    });
  }

  try {
    await loadModuleOptions();
    await loadAudit();
  } catch {
    // no-op
  }
}

async function start() {
  setStatus('Ready', true);
  initModuleNavigation();

  if (pageId === 'iam-identity-center') {
    await initIamIdentityCenterPage();
  } else if (pageId === 'state-import') {
    await initStateImportPage();
  }
}

start();
