/* Dashboard: tenant selector context, KPI cards, recent audit feed. */
(function () {
  'use strict';
  const { Api, TenantCtx, can, h, qs, toast, fmtRelative, fmtDateTime, TimerWidget, HashChainBadge } = window.App;

  async function render(root) {
    const tid = TenantCtx.id;
    const tQuery = tid === null ? {} : { tenant_id: tid };
    const tenant = TenantCtx.current();

    root.innerHTML = `
      <div class="page-head">
        <div>
          <h1>Operations Dashboard
            <span class="badge badge-cyan badge-plain">${h(tenant ? tenant.name : 'All tenants')}</span>
          </h1>
          <p class="sub">Multi-tenant OT fleet health · JIT vendor access · NIS2 Art. 21/23 compliance · tamper-evident audit chain.</p>
        </div>
        <div class="page-actions">
          <button class="btn btn-sm" id="dash-refresh">↻ Refresh</button>
        </div>
      </div>

      <div id="dash-error"></div>

      <div class="grid-4" id="kpi-row">
        <div class="kpi"><div class="kpi-label">OT Assets Online</div><div class="kpi-value" id="kpi-assets">…</div><div class="kpi-sub" id="kpi-assets-sub">loading fleet…</div></div>
        <div class="kpi kpi-green"><div class="kpi-label">Active JIT Grants</div><div class="kpi-value" id="kpi-jit">…</div><div class="kpi-sub" id="kpi-jit-sub">time-bound vendor access</div></div>
        <div class="kpi kpi-amber"><div class="kpi-label">Open Incidents</div><div class="kpi-value" id="kpi-incidents">…</div><div class="kpi-sub" id="kpi-incidents-sub">NIS2 Art. 21/23 tracking</div></div>
        <div class="kpi kpi-red"><div class="kpi-label">Overdue NIS2 Timers</div><div class="kpi-value" id="kpi-overdue">…</div><div class="kpi-sub" id="kpi-overdue-sub">24h / 72h deadlines breached</div></div>
      </div>

      <div class="grid-2">
        <section class="panel">
          <div class="panel-head"><h2>Fleet status grid</h2><span class="pill" id="fleet-count">—</span></div>
          <div id="fleet-grid"><div class="page-loading"><div class="spinner"></div></div></div>
        </section>

        <section class="panel">
          <div class="panel-head"><h2>NIS2 live timers</h2><a href="/incidents" data-link class="btn btn-sm btn-ghost">Open console →</a></div>
          <div id="timer-list"><div class="page-loading"><div class="spinner"></div></div></div>
        </section>
      </div>

      <section class="panel">
        <div class="panel-head">
          <h2>Recent audit events</h2>
          <div style="display:flex;gap:8px;align-items:center">
            <span id="chain-pill" class="pill">verify…</span>
            <a href="/audit" data-link class="btn btn-sm btn-ghost">Full chain →</a>
          </div>
        </div>
        <div id="audit-feed"><div class="page-loading"><div class="spinner"></div></div></div>
      </section>
    `;

    const stopTimers = TimerWidget.tick(root);
    qs('#dash-refresh').addEventListener('click', () => load());
    await load();

    async function load() {
      // ---- Assets ----
      if (can('asset:read')) {
        try {
          const { data: assets } = await Api.get('/assets', tQuery);
          const byStatus = { online: 0, offline: 0, maintenance: 0, alert: 0 };
          assets.forEach((a) => { byStatus[a.status] = (byStatus[a.status] || 0) + 1; });
          qs('#kpi-assets').textContent = byStatus.online || 0;
          qs('#kpi-assets-sub').textContent =
            `${assets.length} total · ${byStatus.alert || 0} alert · ${byStatus.offline || 0} offline · ${byStatus.maintenance || 0} maint`;
          renderFleetGrid(assets);
        } catch (err) {
          qs('#kpi-assets').textContent = '—';
          qs('#fleet-grid').innerHTML = `<div class="empty-state">Fleet unavailable: ${h(err.message)}</div>`;
        }
      } else {
        qs('#kpi-assets').textContent = '🔒';
        qs('#kpi-assets-sub').textContent = 'requires asset:read';
        qs('#fleet-grid').innerHTML = '<div class="empty-state">Requires <code>asset:read</code> in this tenant.</div>';
        qs('#fleet-count').textContent = 'n/a';
      }

      // ---- JIT grants ----
      if (can('jit:read')) {
        try {
          const { data: grants } = await Api.get('/jit/grants', { ...tQuery, is_active: 'true' });
          qs('#kpi-jit').textContent = grants.length;
          const expiringSoon = grants.filter((g) => {
            const dl = App.parseISO(g.valid_until);
            return dl && dl.getTime() - Date.now() < 3600000;
          }).length;
          qs('#kpi-jit-sub').textContent = expiringSoon ? `${expiringSoon} expiring within 1h` : 'all grants healthy';
        } catch (err) {
          qs('#kpi-jit').textContent = '—';
          qs('#kpi-jit-sub').textContent = err.message;
        }
      } else {
        qs('#kpi-jit').textContent = '🔒';
        qs('#kpi-jit-sub').textContent = 'requires jit:read';
      }

      // ---- Incidents + timers ----
      let timers = [];
      if (can('incident:read')) {
        try {
          const { data: incidents } = await Api.get('/incidents', tQuery);
          const openCount = incidents.filter((i) => i.status === 'open' || i.status === 'early_warning_sent').length;
          qs('#kpi-incidents').textContent = openCount;
          qs('#kpi-incidents-sub').textContent = `${incidents.length} total · ${incidents.filter((i) => i.status === 'notified_authority').length} notified`;
        } catch (err) {
          qs('#kpi-incidents').textContent = '—';
          qs('#kpi-incidents-sub').textContent = err.message;
        }
        try {
          const { data } = await Api.get('/incidents/timers', tQuery);
          timers = data || [];
          const overdue = timers.filter((t) => t.is_overdue).length;
          qs('#kpi-overdue').textContent = overdue;
          qs('#kpi-overdue-sub').textContent = overdue ? '⚠ immediate action required' : 'all deadlines met';
          renderTimerList(timers);
        } catch (err) {
          qs('#kpi-overdue').textContent = '—';
          qs('#timer-list').innerHTML = `<div class="empty-state">${h(err.message)}</div>`;
        }
      } else {
        qs('#kpi-incidents').textContent = '🔒';
        qs('#kpi-overdue').textContent = '🔒';
        qs('#timer-list').innerHTML = '<div class="empty-state">Requires <code>incident:read</code> in this tenant.</div>';
      }

      // ---- Audit feed ----
      if (can('audit:read')) {
        try {
          const { data: logs } = await Api.get('/audit/logs', { ...tQuery, limit: 8 });
          renderAuditFeed(logs || []);
        } catch (err) {
          qs('#audit-feed').innerHTML = `<div class="empty-state">${h(err.message)}</div>`;
        }
        try {
          const { data: verify } = await Api.get('/audit/verify');
          const pill = qs('#chain-pill');
          if (verify.valid) {
            pill.className = 'pill pill-ok';
            pill.textContent = `✔ chain valid · ${verify.checked_count} entries`;
            HashChainBadge.set('valid', `chain valid · ${verify.checked_count} links`);
          } else {
            pill.className = 'pill pill-err';
            pill.textContent = `✘ tamper @ #${verify.first_mismatch ? verify.first_mismatch.sequence_no : '?'}`;
            HashChainBadge.set('invalid', 'CHAIN BROKEN');
          }
        } catch { /* badge handled elsewhere */ }
      } else {
        qs('#audit-feed').innerHTML = '<div class="empty-state">Requires <code>audit:read</code> in this tenant.</div>';
        qs('#chain-pill').textContent = 'n/a';
      }
    }

    function renderFleetGrid(assets) {
      qs('#fleet-count').textContent = `${assets.length} assets`;
      if (!assets.length) {
        qs('#fleet-grid').innerHTML = '<div class="empty-state"><div class="big">⛭</div>No assets in this tenant.</div>';
        return;
      }
      const badgeFor = (s) => ({
        online: 'badge-green', offline: 'badge-muted', maintenance: 'badge-amber', alert: 'badge-red',
      }[s] || 'badge-muted');
      qs('#fleet-grid').innerHTML = `
        <div class="table-wrap"><table class="data">
          <thead><tr><th>Tag</th><th>Name</th><th>Type</th><th>Site</th><th>Status</th><th>Last seen</th></tr></thead>
          <tbody>
            ${assets.map((a) => `
              <tr class="${a.status === 'alert' ? 'row-overdue' : ''}">
                <td class="mono">${h(a.asset_tag)}</td>
                <td>${h(a.name)}</td>
                <td><span class="badge badge-cyan badge-plain">${h(a.type)}</span></td>
                <td class="muted">${h(a.site || '—')}</td>
                <td><span class="badge ${badgeFor(a.status)}">${h(a.status)}</span></td>
                <td class="muted nowrap">${h(fmtRelative(a.last_seen))}</td>
              </tr>`).join('')}
          </tbody>
        </table></div>`;
    }

    function renderTimerList(timers) {
      const active = timers.filter((t) => t.status === 'open' || t.status === 'early_warning_sent');
      const rest = timers.filter((t) => !active.includes(t));
      const list = [...active, ...rest].slice(0, 4);
      if (!list.length) {
        qs('#timer-list').innerHTML = '<div class="empty-state"><div class="big">✔</div>No NIS2 incidents declared.</div>';
        return;
      }
      qs('#timer-list').innerHTML = list.map((t) => `
        <div class="panel incident-card sev-${h(t.severity)} ${t.is_overdue ? 'is-overdue' : ''}" style="margin-bottom:10px;padding:12px 14px">
          <div style="display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap">
            <div>
              <strong>#${t.id} ${h(t.title)}</strong>
              <span class="badge ${t.is_overdue ? 'badge-red' : 'badge-cyan'}" style="margin-left:8px">${h(t.timer_state)}</span>
            </div>
            <span class="muted" style="font-size:11.5px">${h(t.status)}</span>
          </div>
          ${TimerWidget.html(t)}
        </div>`).join('');
    }

    function renderAuditFeed(logs) {
      if (!logs.length) {
        qs('#audit-feed').innerHTML = '<div class="empty-state"><div class="big">🔗</div>No audit events yet.</div>';
        return;
      }
      qs('#audit-feed').innerHTML = `
        <div class="table-wrap"><table class="data">
          <thead><tr><th>Seq</th><th>When</th><th>Action</th><th>Target</th><th>Actor</th><th>Hash</th></tr></thead>
          <tbody>
            ${logs.map((l) => `
              <tr>
                <td class="mono">#${l.sequence_no}</td>
                <td class="muted nowrap" title="${h(fmtDateTime(l.event_time))}">${h(fmtRelative(l.event_time))}</td>
                <td><span class="badge badge-amber badge-plain mono">${h(l.action)}</span></td>
                <td class="muted mono">${h(l.target_type)}:${h(l.target_id)}</td>
                <td class="muted">${l.actor_user_id ? '#' + h(l.actor_user_id) : 'system'}</td>
                <td class="hash-cell" title="${h(l.hash)}"><span class="h-short">${h((l.hash || '').slice(0, 12))}…</span><span class="h-full">${h(l.hash)}</span></td>
              </tr>`).join('')}
          </tbody>
        </table></div>`;
    }

    return stopTimers;
  }

  window.App.registerRoute('dashboard', '/', render);
})();
