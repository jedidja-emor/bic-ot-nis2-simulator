/* NIS2 incidents: declare, live 24h/72h countdowns, Art.21/23 transitions. */
(function () {
  'use strict';
  const { Api, TenantCtx, Session, can, h, qs, qsa, toast, fmtDateTime, fmtRelative, TimerWidget, HashChainBadge } = window.App;

  // One-click NIS2 scenarios used to exercise the Art.21 / Art.23 timers.
  const SCENARIOS = [
    {
      title: 'Ransomware on OT historian',
      description: 'Encryption detected on the process historian; HMI telemetry unavailable. Affected segment isolated pending forensics.',
      severity: 'critical', article: 'both', cls: 'btn-danger',
    },
    {
      title: 'PLC firmware integrity anomaly',
      description: 'Unexpected firmware checksum on a shop-floor controller. Production halted pending integrity verification.',
      severity: 'high', article: 'both', cls: 'btn-primary',
    },
    {
      title: 'Substation RTU communications loss',
      description: 'Feeder RTU stopped reporting heartbeats; operators cannot read breaker state.',
      severity: 'high', article: '21', cls: 'btn-cyan',
    },
    {
      title: 'Chlorine sensor drift above threshold',
      description: 'Treatment plant sensor readings outside the safe band; manual sampling initiated.',
      severity: 'medium', article: '23', cls: 'btn-success',
    },
  ];

  const SEVERITIES = ['low', 'medium', 'high', 'critical'];
  const SEV_BADGE = { low: 'badge-green', medium: 'badge-cyan', high: 'badge-amber', critical: 'badge-red' };
  const STATE_BADGE = {
    early_warning_pending: 'badge-cyan',
    early_warning_overdue: 'badge-red',
    notification_pending: 'badge-violet',
    notification_overdue: 'badge-red',
    notified: 'badge-green',
    complete: 'badge-muted',
    unknown: 'badge-muted',
  };
  const STATUS_LABEL = {
    open: 'open',
    early_warning_sent: 'Art.21 sent',
    notified_authority: 'authority notified',
    resolved: 'resolved',
    closed: 'closed',
  };

  async function render(root) {
    const canDeclare = can('incident:declare');
    const canEarly = can('incident:early_warning');
    const canNotify = can('incident:notify');
    const canRead = can('incident:read');

    root.innerHTML = `
      <div class="page-head">
        <div>
          <h1>NIS2 Incident Console <span class="badge badge-red badge-plain">Art. 21 · Art. 23</span></h1>
          <p class="sub">
            Article 21 early warning ≤ <strong>24h</strong> · Article 23 authority notification ≤ <strong>72h</strong> from
            <code>declared_at</code>. Deadlines are authoritative from the API; client countdowns tick live and refresh every 60s.
          </p>
        </div>
        <div class="page-actions">
          <span class="pill" id="overdue-pill">timers …</span>
          <button class="btn btn-sm" id="inc-refresh">↻ Refresh</button>
        </div>
      </div>

      ${canDeclare ? `
      <section class="panel">
        <div class="panel-head"><h2>Declare incident (starts both timers)</h2></div>
        <form id="declare-form">
          <div class="form-row-3">
            <label class="field"><span>Title</span>
              <input name="title" required minlength="3" maxlength="255" placeholder="Ransomware on historian" />
            </label>
            <label class="field"><span>Severity</span>
              <select name="severity">${SEVERITIES.map((s) => `<option${s === 'high' ? ' selected' : ''}>${s}</option>`).join('')}</select>
            </label>
            <label class="field"><span>Article</span>
              <select name="article">
                <option value="both" selected>both (21 + 23)</option>
                <option value="21">21 only</option>
                <option value="23">23 only</option>
              </select>
            </label>
          </div>
          <label class="field"><span>Description</span>
            <textarea name="description" required minlength="3" placeholder="What happened, blast radius, containment steps…"></textarea>
          </label>
          ${needsTenantPicker() ? `
          <label class="field"><span>Tenant (required)</span>
            <select name="tenant_id" id="declare-tenant" required>
              ${TenantCtx.list().map((t) => `<option value="${t.id}"${TenantCtx.id === t.id ? ' selected' : ''}>${h(t.name)} · ${h(t.sector)}</option>`).join('')}
            </select>
          </label>` : ''}
          <p class="form-error hidden" id="declare-error"></p>
          <button class="btn btn-primary" type="submit">⚠ Declare incident</button>
        </form>
      </section>

      <section class="panel">
        <div class="panel-head">
          <h2>⚡ Quick NIS2 simulations</h2>
          <span class="pill">one-click · starts 24h / 72h timers</span>
        </div>
        <p class="muted" style="font-size:12.5px;margin-top:-4px">
          Fire a pre-built OT scenario to exercise the Article 21 early-warning and Article 23 authority-notification deadlines.
        </p>
        <div class="scenario-grid">
          ${SCENARIOS.map((s, i) => `
            <button type="button" class="btn ${s.cls}" data-sim="${i}">
              <span class="sim-mark">⚠</span>
              <span><strong>${h(s.title)}</strong><br/><small>${h(s.severity)} · Art.${h(s.article)}</small></span>
            </button>`).join('')}
        </div>
      </section>` : `
      <div class="info-banner">Your role lacks <code>incident:declare</code> — viewing existing incidents only.</div>`}

      <div id="incidents-body">
        ${canRead ? '<div class="page-loading"><div class="spinner"></div></div>'
                  : '<div class="empty-state"><div class="big">🔒</div>Requires <code>incident:read</code> in this tenant.</div>'}
      </div>
    `;

    const stopTimers = TimerWidget.tick(root);
    qs('#inc-refresh').addEventListener('click', load);
    if (canDeclare) {
      qs('#declare-form').addEventListener('submit', declareIncident);
      qsa('[data-sim]').forEach((btn) => {
        btn.addEventListener('click', () => simulate(parseInt(btn.dataset.sim, 10)));
      });
    }

    if (canRead) {
      await load();
      // Authoritative refresh every 60s (server recomputes timer_state).
      const interval = setInterval(load, 60000);
      return () => { clearInterval(interval); stopTimers(); };
    }
    return stopTimers;

    async function load() {
      const body = qs('#incidents-body');
      if (!canRead) return;
      try {
        const tid = TenantCtx.id;
        const { data: timers } = await Api.get('/incidents/timers', tid === null ? {} : { tenant_id: tid });
        renderIncidents(timers || []);
        const overdue = (timers || []).filter((t) => t.is_overdue).length;
        const pill = qs('#overdue-pill');
        if (overdue) {
          pill.className = 'pill pill-err';
          pill.textContent = `⚠ ${overdue} overdue deadline${overdue > 1 ? 's' : ''}`;
        } else {
          pill.className = 'pill pill-ok';
          pill.textContent = '✔ all NIS2 deadlines met';
        }
      } catch (err) {
        body.innerHTML = `<div class="error-banner"><span>${h(err.message)}</span>
          <button class="btn btn-sm btn-danger" onclick="location.reload()">Retry</button></div>`;
      }
    }

    function renderIncidents(list) {
      const body = qs('#incidents-body');
      if (!list.length) {
        body.innerHTML = '<div class="empty-state"><div class="big">✔</div>No incidents declared for this tenant.</div>';
        return;
      }
      body.innerHTML = list.map((inc) => {
        const isOverdue = inc.is_overdue;
        const actions = [];
        if (inc.status === 'open' && canEarly) {
          actions.push(`<button class="btn btn-sm btn-cyan" data-ew="${inc.id}">Send Early Warning (Art.21)</button>`);
        } else if (inc.status === 'open') {
          actions.push(`<button class="btn btn-sm" disabled title="requires incident:early_warning">Send Early Warning</button>`);
        }
        if (inc.status === 'early_warning_sent' && canNotify) {
          actions.push(`<button class="btn btn-sm btn-primary" data-notify="${inc.id}">Notify Authority (Art.23)</button>`);
        } else if (inc.status === 'early_warning_sent') {
          actions.push(`<button class="btn btn-sm" disabled title="requires incident:notify">Notify Authority</button>`);
        }
        if (canDeclare && inc.status !== 'resolved' && inc.status !== 'closed') {
          actions.push(`<button class="btn btn-sm btn-success" data-resolve="${inc.id}">Resolve</button>`);
        }
        if (canDeclare && inc.status === 'resolved') {
          actions.push(`<button class="btn btn-sm" data-close="${inc.id}">Close</button>`);
        }

        return `
          <section class="panel incident-card sev-${h(inc.severity)} ${isOverdue ? 'is-overdue' : ''}" data-inc="${inc.id}">
            <div class="panel-head" style="margin-bottom:4px">
              <h2 style="color:var(--text)">
                #${inc.id} ${h(inc.title)}
                <span class="badge ${SEV_BADGE[inc.severity] || 'badge-muted'}" style="margin-left:6px">${h(inc.severity)}</span>
                <span class="badge badge-muted badge-plain mono">Art.${h(inc.article)}</span>
                <span class="badge ${STATE_BADGE[inc.timer_state] || 'badge-muted'} state-chip">${h(inc.timer_state)}</span>
                <span class="badge ${isOverdue ? 'badge-red' : 'badge-amber'}">${h(STATUS_LABEL[inc.status] || inc.status)}</span>
              </h2>
              <span class="muted" style="font-size:11.5px" title="${h(fmtDateTime(inc.declared_at))}">
                declared ${h(fmtRelative(inc.declared_at))}
              </span>
            </div>
            <p class="muted" style="font-size:13px;margin:4px 0 2px">${h(inc.description)}</p>
            <p class="faint mono" style="font-size:11px;margin:2px 0 0">
              tenant #${inc.tenant_id}
              · EW sent: ${h(inc.early_warning_sent_at || '—')}
              · authority: ${h(inc.notification_sent_at || '—')}
            </p>

            ${TimerWidget.html(inc)}

            <div class="page-actions" style="margin-top:8px">${actions.join('')}</div>
          </section>`;
      }).join('');

      body.querySelectorAll('[data-ew]').forEach((btn) => btn.addEventListener('click', () => transition(btn.dataset.ew, 'early-warning', 'Art.21 early warning sent')));
      body.querySelectorAll('[data-notify]').forEach((btn) => btn.addEventListener('click', () => transition(btn.dataset.notify, 'notify', 'Art.23 authority notification sent')));
      body.querySelectorAll('[data-resolve]').forEach((btn) => btn.addEventListener('click', () => patchStatus(btn.dataset.resolve, 'resolved', 'Incident resolved.')));
      body.querySelectorAll('[data-close]').forEach((btn) => btn.addEventListener('click', () => patchStatus(btn.dataset.close, 'closed', 'Incident closed.')));
      // The page-level TimerWidget.tick(root) already covers freshly rendered
      // widgets because it re-queries the whole root on every tick.
    }

    async function transition(id, path, successMsg) {
      try {
        const { data } = await Api.post(`/incidents/${id}/${path}`, {});
        if (data && data.is_overdue) {
          toast(`${successMsg} — but AFTER the regulatory deadline (late).`, 'warn', 'Overdue');
        } else {
          toast(successMsg, 'success');
        }
        HashChainBadge.refresh();
        load();
      } catch (err) {
        toast(err.message, 'error', 'Transition failed');
      }
    }

    async function patchStatus(id, status, successMsg) {
      try {
        await Api.patch(`/incidents/${id}`, { status });
        toast(successMsg, 'success');
        HashChainBadge.refresh();
        load();
      } catch (err) {
        toast(err.message, 'error', 'Update failed');
      }
    }

    /** Platform admins (or users with no single tenant selected) must pick one. */
    function needsTenantPicker() {
      return TenantCtx.id === null || !!(Session.ctx && Session.ctx.is_platform_admin);
    }

    /** Resolve the tenant_id for a declare call from the form/context. */
    function declareTenant() {
      const sel = qs('#declare-tenant');
      if (sel && sel.value) return parseInt(sel.value, 10);
      return TenantCtx.id;
    }

    async function simulate(index) {
      const s = SCENARIOS[index];
      if (!s) return;
      const tid = declareTenant();
      if (tid === null) {
        toast('Select a tenant context before simulating an incident.', 'warn', 'No tenant');
        return;
      }
      try {
        const { data } = await Api.post('/incidents', {
          tenant_id: tid,
          title: s.title,
          description: s.description,
          severity: s.severity,
          article: s.article,
        });
        toast(`Simulated incident #${data.id} declared — Art.21 ${data.early_warning_deadline} · Art.23 ${data.notification_deadline}`, 'success', 'NIS2 simulation');
        HashChainBadge.refresh();
        load();
      } catch (err) {
        toast(err.message, 'error', 'Simulation failed');
      }
    }

    async function declareIncident(e) {
      e.preventDefault();
      const f = e.target;
      const errEl = qs('#declare-error');
      errEl.classList.add('hidden');
      try {
        const body = {
          title: f.title.value.trim(),
          description: f.description.value.trim(),
          severity: f.severity.value,
          article: f.article.value,
        };
        const tid = declareTenant();
        if (tid === null) {
          errEl.textContent = 'Select a tenant context before declaring an incident.';
          errEl.classList.remove('hidden');
          return;
        }
        body.tenant_id = tid;
        const { data } = await Api.post('/incidents', body);
        toast(`Incident #${data.id} declared — Art.21 ${data.early_warning_deadline} · Art.23 ${data.notification_deadline}`, 'success', 'Timers started');
        f.reset();
        HashChainBadge.refresh();
        load();
      } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
      }
    }
  }

  window.App.registerRoute('incidents', '/incidents', render);
})();
