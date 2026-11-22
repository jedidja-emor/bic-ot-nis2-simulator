/* Audit log: paginated, filterable, hash-chained + chain verification UI. */
(function () {
  'use strict';
  const { Api, TenantCtx, can, h, qs, toast, fmtDateTime, fmtRelative, HashChainBadge, Modal } = window.App;

  const PAGE_SIZE = 25;
  const STREAM_MS = 15000;
  let page = 0;
  let total = 0;
  let verifying = false;
  let streamTimer = null;

  const cleanup = () => {
    if (streamTimer) clearInterval(streamTimer);
    streamTimer = null;
  };

  async function render(root) {
    const canRead = can('audit:read');
    page = 0;

    root.innerHTML = `
      <div class="page-head">
        <div>
          <h1>Audit Chain <span class="badge badge-violet badge-plain">append-only · sha256</span></h1>
          <p class="sub">
            Every security-relevant event is hash-chained:
            <code class="mono">sha256(seq|prev|time|actor|action|type|target|details)</code>.
            Verification recomputes the full chain and reports the first mismatch.
          </p>
        </div>
        <div class="page-actions">
          <button class="btn btn-cyan" id="btn-verify" ${canRead ? '' : 'disabled'}>🔗 Verify chain</button>
          <button class="btn btn-sm" id="audit-refresh">↻ Refresh</button>
          <button class="btn btn-sm" id="audit-live" title="Auto-refresh the audit stream every 15s" ${canRead ? '' : 'disabled'}>▶ Live stream</button>
        </div>
      </div>

      <div id="verify-banner-slot"></div>

      <div class="filter-bar panel" style="padding:12px 14px">
        <label class="field"><span>Tenant</span>
          <select id="a-tenant">
            <option value="">${TenantCtx.list().length && TenantCtx.id !== null ? 'current context only' : 'visible scope'}</option>
            ${TenantCtx.list().map((t) => `<option value="${t.id}"${TenantCtx.id === t.id ? ' selected' : ''}>${h(t.name)}</option>`).join('')}
          </select>
        </label>
        <label class="field"><span>Action</span>
          <input id="a-action" placeholder="incident:declare" />
        </label>
        <label class="field"><span>Actor user id</span>
          <input id="a-actor" type="number" min="1" placeholder="e.g. 2" />
        </label>
        <label class="field"><span>Since (UTC)</span>
          <input id="a-since" type="datetime-local" />
        </label>
        <label class="field"><span>Until (UTC)</span>
          <input id="a-until" type="datetime-local" />
        </label>
        <div style="display:flex;gap:8px;align-self:flex-end">
          <button class="btn btn-sm" id="a-apply">Apply</button>
          <button class="btn btn-sm btn-ghost" id="a-clear">Clear</button>
        </div>
      </div>

      <div id="audit-body">
        ${canRead ? '<div class="page-loading"><div class="spinner"></div></div>'
                  : '<div class="empty-state"><div class="big">🔒</div>Requires <code>audit:read</code> in this tenant.</div>'}
      </div>

      ${canRead ? `
      <div class="pager" id="audit-pager">
        <span id="pager-info">—</span>
        <span class="btns">
          <button class="btn btn-sm" id="page-prev">← Prev</button>
          <button class="btn btn-sm" id="page-next">Next →</button>
        </span>
      </div>` : ''}
    `;

    if (!canRead) return cleanup;

    qs('#btn-verify').addEventListener('click', verifyChain);
    qs('#audit-refresh').addEventListener('click', () => { page = 0; load(); });
    qs('#audit-live').addEventListener('click', () => {
      const btn = qs('#audit-live');
      if (streamTimer) {
        clearInterval(streamTimer);
        streamTimer = null;
        btn.textContent = '▶ Live stream';
        btn.className = 'btn btn-sm';
        toast('Audit stream paused.', 'info');
      } else {
        streamTimer = setInterval(load, STREAM_MS);
        btn.textContent = '⏸ Pause stream';
        btn.className = 'btn btn-sm btn-success';
        toast(`Audit stream live — refreshing every ${STREAM_MS / 1000}s.`, 'success');
      }
    });
    qs('#a-apply').addEventListener('click', () => { page = 0; load(); });
    qs('#a-clear').addEventListener('click', () => {
      ['a-action', 'a-actor', 'a-since', 'a-until'].forEach((id) => { qs('#' + id).value = ''; });
      qs('#a-tenant').value = '';
      page = 0;
      load();
    });
    qs('#page-prev').addEventListener('click', () => { if (page > 0) { page -= 1; load(); } });
    qs('#page-next').addEventListener('click', () => {
      if ((page + 1) * PAGE_SIZE < total) { page += 1; load(); }
    });

    await load();

    async function currentFilters() {
      const filters = { limit: PAGE_SIZE, offset: page * PAGE_SIZE };
      const tenantSel = qs('#a-tenant');
      const explicitTenant = tenantSel.value;
      if (explicitTenant) {
        filters.tenant_id = explicitTenant;
      } else if (TenantCtx.id !== null) {
        filters.tenant_id = TenantCtx.id;
      }
      const action = qs('#a-action').value.trim();
      if (action) filters.action = action;
      const actor = qs('#a-actor').value.trim();
      if (actor) filters.actor_user_id = actor;
      const since = qs('#a-since').value;
      if (since) filters.since = window.App.fromLocalInput(since);
      const until = qs('#a-until').value;
      if (until) filters.until = window.App.fromLocalInput(until);
      return filters;
    }

    async function load() {
      const body = qs('#audit-body');
      try {
        const filters = await currentFilters();
        const { data, headers } = await Api.get('/audit/logs', filters);
        total = parseInt(headers.get('X-Total-Count') || '0', 10) || (data || []).length;
        renderRows(data || []);
        renderPager();
      } catch (err) {
        body.innerHTML = `<div class="error-banner"><span>${h(err.message)}</span></div>`;
      }
    }

    function renderPager() {
      const info = qs('#pager-info');
      if (!info) return;
      const from = total === 0 ? 0 : page * PAGE_SIZE + 1;
      const to = Math.min(total, (page + 1) * PAGE_SIZE);
      info.textContent = `${from}–${to} of ${total} entries · page ${page + 1}`;
      qs('#page-prev').disabled = page === 0;
      qs('#page-next').disabled = (page + 1) * PAGE_SIZE >= total;
    }

    function renderRows(logs) {
      const body = qs('#audit-body');
      if (!logs.length) {
        body.innerHTML = '<div class="empty-state"><div class="big">🔗</div>No audit entries match these filters.</div>';
        return;
      }
      body.innerHTML = `
        <div class="table-wrap"><table class="data">
          <thead>
            <tr>
              <th>Seq</th><th>Event time</th><th>Action</th><th>Target</th>
              <th>Actor</th><th>Tenant</th><th>Hash / previous</th><th></th>
            </tr>
          </thead>
          <tbody>
            ${logs.map((l) => `
              <tr>
                <td class="mono"><strong>#${l.sequence_no}</strong></td>
                <td class="nowrap" title="${h(fmtDateTime(l.event_time))}">
                  ${h(fmtRelative(l.event_time))}<br/><small class="faint mono">${h(l.event_time)}</small>
                </td>
                <td><span class="badge badge-amber badge-plain mono">${h(l.action)}</span></td>
                <td class="mono muted">${h(l.target_type)}:${h(l.target_id)}</td>
                <td class="muted">${l.actor_user_id ? 'user #' + h(l.actor_user_id) : 'system'}</td>
                <td class="muted">${l.tenant_id === null ? '<span class="faint">platform</span>' : '#' + h(l.tenant_id)}</td>
                <td class="hash-cell" title="hash: ${h(l.hash)}&#10;previous: ${h(l.previous_hash)}">
                  <span class="h-short">${h((l.hash || '').slice(0, 14))}…</span>
                  <span class="h-full">${h(l.hash)}<br/><span class="faint">prev ${h((l.previous_hash || '').slice(0, 14))}…</span></span>
                </td>
                <td class="actions">
                  <button class="btn btn-sm btn-ghost" data-verify-prefix="${l.id}" title="Verify chain up to this entry">verify ↗</button>
                </td>
              </tr>`).join('')}
          </tbody>
        </table></div>`;

      body.querySelectorAll('[data-verify-prefix]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            const { data } = await Api.get(`/audit/verify/${btn.dataset.verifyPrefix}`);
            showVerifyBanner(data, `Prefix ≤ entry ${data.entry_id} (seq #${data.sequence_no})`);
          } catch (err) { toast(err.message, 'error'); }
        });
      });
    }

    async function verifyChain() {
      if (verifying) return;
      verifying = true;
      const btn = qs('#btn-verify');
      const original = btn.textContent;
      btn.disabled = true;
      btn.textContent = 'Verifying…';
      try {
        const { data } = await Api.get('/audit/verify');
        showVerifyBanner(data, 'Full chain');
        if (data.valid) {
          toast(`Chain valid — ${data.checked_count} entries recomputed.`, 'success', 'Integrity OK');
          HashChainBadge.set('valid', `chain valid · ${data.checked_count} links`);
        } else {
          const m = data.first_mismatch || {};
          toast(`Tamper detected at sequence #${m.sequence_no} (${m.reason}).`, 'error', 'Chain broken');
          HashChainBadge.set('invalid', `TAMPER @ #${m.sequence_no || '?'}`);
        }
      } catch (err) {
        toast(err.message, 'error', 'Verification failed');
      } finally {
        verifying = false;
        btn.disabled = false;
        btn.textContent = original;
      }
    }

    function showVerifyBanner(result, scopeLabel) {
      const slot = qs('#verify-banner-slot');
      const m = result.first_mismatch;
      if (result.valid) {
        slot.innerHTML = `
          <div class="chain-verify-banner valid">
            <span class="cv-icon">✅</span>
            <div>
              <div class="cv-title">Chain valid — ${h(scopeLabel)} · ${result.checked_count} entries</div>
              <div class="cv-sub">Every recomputed sha256 matches its stored hash and previous-hash linkage.</div>
            </div>
            <button class="btn btn-sm btn-ghost" style="margin-left:auto" onclick="this.closest('.chain-verify-banner').remove()">×</button>
          </div>`;
      } else {
        slot.innerHTML = `
          <div class="chain-verify-banner invalid">
            <span class="cv-icon">🚨</span>
            <div>
              <div class="cv-title">Tamper detected — ${h(scopeLabel)} at entry #${h(m && m.entry_id)} (seq #${h(m && m.sequence_no)})</div>
              <div class="cv-sub">reason: ${h(m && m.reason)} · expected: ${h(m && m.expected)} · actual: ${h(m && m.actual)}</div>
            </div>
            <button class="btn btn-sm btn-ghost" style="margin-left:auto" onclick="this.closest('.chain-verify-banner').remove()">×</button>
          </div>`;
      }
    }

    return cleanup;
  }

  window.App.registerRoute('audit', '/audit', render);
})();
