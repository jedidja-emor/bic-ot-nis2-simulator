/* JIT vendor access: request → approve/reject → active grants → revoke. */
(function () {
  'use strict';
  const { Api, TenantCtx, can, h, qs, toast, Modal, fmtRelative, fmtDateTime, TimerWidget, HashChainBadge } = window.App;

  const PERM_OPTIONS = [
    'asset:read', 'asset:jit_access', 'asset:write',
    'incident:read', 'jit:read',
  ];

  async function render(root) {
    const canApprove = can('jit:approve');
    const canRequest = can('jit:request');
    const canRead = can('jit:read');
    const ctxUser = (window.App.Session.ctx || {}).user || {};

    root.innerHTML = `
      <div class="page-head">
        <div>
          <h1>Just-In-Time Access <span class="badge badge-amber badge-plain">NIS2 · time-bound</span></h1>
          <p class="sub">Vendor access is approval-gated and auto-expires at <code>valid_until</code>. The backend enforces the grant window on every OT action.</p>
        </div>
        <div class="page-actions">
          <button class="btn btn-sm" id="jit-refresh">↻ Refresh</button>
        </div>
      </div>

      <div class="grid-2">
        <section class="panel">
          <div class="panel-head">
            <h2>1 · Access requests ${canApprove ? '(approver)' : '(read-only)'}</h2>
            <select id="f-req-status" style="width:auto">
              <option value="pending">pending</option>
              <option value="">all statuses</option>
              <option value="approved">approved</option>
              <option value="rejected">rejected</option>
              <option value="revoked">revoked</option>
            </select>
          </div>
          <div id="requests-body"><div class="page-loading"><div class="spinner"></div></div></div>
        </section>

        <div>
          ${canRequest ? `
          <section class="panel">
            <div class="panel-head"><h2>2 · Request access</h2></div>
            <form id="new-request-form">
              <label class="field"><span>Target asset (optional — blank = tenant-level)</span>
                <select name="asset_id" id="req-asset"><option value="">— tenant-level —</option></select>
              </label>
              <label class="field"><span>Justification</span>
                <textarea name="reason" required minlength="3" placeholder="Emergency pump calibration window requested by ops…"></textarea>
              </label>
              <div class="field">
                <span>Requested permissions</span>
                <div class="checkbox-grid" id="req-perms">
                  ${PERM_OPTIONS.map((p) => `
                    <label><input type="checkbox" name="perm" value="${p}"${p === 'asset:read' || p === 'asset:jit_access' ? ' checked' : ''}/> <span class="mono">${p}</span></label>
                  `).join('')}
                </div>
              </div>
              <label class="field"><span>Requested until (UTC)</span>
                <input type="datetime-local" name="requested_until" required />
              </label>
              <p class="form-error hidden" id="req-error"></p>
              <button class="btn btn-primary btn-block" type="submit">Submit JIT request</button>
            </form>
          </section>` : `
          <div class="info-banner">Your role lacks <code>jit:request</code> — you cannot open new access windows.</div>`}

          <section class="panel">
            <div class="panel-head"><h2>3 · My active grants</h2><span class="pill" id="my-grants-count">—</span></div>
            <div id="my-grants-body"><div class="page-loading"><div class="spinner"></div></div></div>
          </section>
        </div>
      </div>

      <section class="panel">
        <div class="panel-head">
          <h2>All grants in tenant</h2>
          <span class="pill" id="all-grants-count">—</span>
        </div>
        <div id="all-grants-body"><div class="page-loading"><div class="spinner"></div></div></div>
      </section>
    `;

    const stopTimers = TimerWidget.tick(root);
    qs('#jit-refresh').addEventListener('click', load);
    qs('#f-req-status').addEventListener('change', loadRequests);
    if (canRequest) qs('#new-request-form').addEventListener('submit', submitRequest);
    await load();

    async function load() {
      await Promise.all([loadRequests(), loadMyGrants(), loadAllGrants()]);
      if (canRequest) await fillAssetSelect();
    }

    async function fillAssetSelect() {
      const sel = qs('#req-asset');
      if (!sel) return;
      try {
        const tid = TenantCtx.id;
        const { data } = await Api.get('/assets', tid === null ? {} : { tenant_id: tid });
        sel.innerHTML = '<option value="">— tenant-level —</option>' +
          (data || []).map((a) => `<option value="${a.id}">${h(a.asset_tag)} · ${h(a.name)}</option>`).join('');
      } catch { /* leave default */ }
    }

    async function loadRequests() {
      const body = qs('#requests-body');
      if (!canRead) {
        body.innerHTML = '<div class="empty-state">Requires <code>jit:read</code>.</div>';
        return;
      }
      try {
        const status = qs('#f-req-status').value;
        const tid = TenantCtx.id;
        const { data } = await Api.get('/jit/requests', {
          ...(tid === null ? {} : { tenant_id: tid }),
          status: status || undefined,
        });
        renderRequests(data || []);
      } catch (err) {
        body.innerHTML = `<div class="error-banner"><span>${h(err.message)}</span></div>`;
      }
    }

    function renderRequests(requests) {
      const body = qs('#requests-body');
      if (!requests.length) {
        body.innerHTML = '<div class="empty-state"><div class="big">⏱</div>No JIT requests in this view.</div>';
        return;
      }
      body.innerHTML = `
        <div class="table-wrap"><table class="data">
          <thead><tr><th>#</th><th>Requester</th><th>Asset</th><th>Permissions</th><th>Until</th><th>Status</th><th></th></tr></thead>
          <tbody>
            ${requests.map((r) => {
              const pending = r.status === 'pending';
              return `
              <tr>
                <td class="mono">#${r.id}</td>
                <td>user #${r.requesting_user_id}<br/><small class="faint">${h(fmtRelative(r.created_at))}</small></td>
                <td class="mono">${r.asset_id ? '#' + h(r.asset_id) : '<span class="muted">tenant</span>'}</td>
                <td class="mono" style="font-size:11px">${h((r.requested_permissions || []).join(', '))}</td>
                <td class="mono nowrap" style="font-size:11.5px">${h(r.requested_until)}</td>
                <td><span class="badge ${statusBadge(r.status)}">${h(r.status)}</span></td>
                <td class="actions">
                  ${pending && canApprove ? `
                    <button class="btn btn-sm btn-success" data-approve="${r.id}">Approve</button>
                    <button class="btn btn-sm btn-danger" data-reject="${r.id}">Reject</button>` : ''}
                </td>
              </tr>`;
            }).join('')}
          </tbody>
        </table></div>`;

      body.querySelectorAll('[data-approve]').forEach((btn) => {
        btn.addEventListener('click', () => openApprove(parseInt(btn.dataset.approve, 10), requests));
      });
      body.querySelectorAll('[data-reject]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          if (!confirm('Reject this JIT request?')) return;
          try {
            await Api.post(`/jit/requests/${btn.dataset.reject}/reject`, { reason: 'rejected from console' });
            toast('Request rejected.', 'success');
            load();
          } catch (err) { toast(err.message, 'error'); }
        });
      });
    }

    function openApprove(requestId, requests) {
      const r = requests.find((x) => x.id === requestId);
      if (!r) return;
      Modal.open(`
        <h2>Approve JIT request #${r.id} <button class="modal-close" aria-label="Close">×</button></h2>
        <p class="muted" style="font-size:13px">Justification: ${h(r.reason)}</p>
        <form id="approve-form">
          <label class="field"><span>Granted permissions (comma-separated — must be ⊆ requested)</span>
            <input name="granted_permissions" class="mono" value="${h((r.requested_permissions || []).join(','))}" />
          </label>
          <label class="field"><span>Valid until (UTC, capped at requested ${h(r.requested_until)})</span>
            <input type="datetime-local" name="valid_until" />
          </label>
          <p class="form-hint">Leave valid-until blank to grant the full requested window. A grant is active only while <code>valid_from ≤ now ≤ valid_until</code>.</p>
          <p class="form-error hidden" id="approve-error"></p>
          <div class="modal-actions">
            <button type="button" class="btn" data-modal-close>Cancel</button>
            <button type="submit" class="btn btn-success">Approve &amp; grant</button>
          </div>
        </form>
      `);
      qs('#approve-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const f = e.target;
        const errEl = qs('#approve-error');
        errEl.classList.add('hidden');
        try {
          const body = { granted_permissions: f.granted_permissions.value.trim() || null };
          if (f.valid_until.value) body.valid_until = window.App.fromLocalInput(f.valid_until.value);
          const { data } = await Api.post(`/jit/requests/${r.id}/approve`, body);
          Modal.close();
          toast(`Grant #${data.grant.id} active until ${data.grant.valid_until}.`, 'success', 'Approved');
          load();
        } catch (err) {
          errEl.textContent = err.message;
          errEl.classList.remove('hidden');
        }
      });
    }

    async function loadMyGrants() {
      const body = qs('#my-grants-body');
      try {
        const { data } = await Api.get('/jit/my-grants', { include_inactive: 'true' });
        const grants = data || [];
        qs('#my-grants-count').textContent = `${grants.filter((g) => g.is_active).length} active`;
        if (!grants.length) {
          body.innerHTML = '<div class="empty-state">No JIT grants for your account.</div>';
          return;
        }
        body.innerHTML = grants.map((g) => grantRow(g, true)).join('');
        wireGrantButtons(body);
      } catch (err) {
        body.innerHTML = `<div class="empty-state">${h(err.message)}</div>`;
      }
    }

    async function loadAllGrants() {
      const body = qs('#all-grants-body');
      if (!canRead) {
        body.innerHTML = '<div class="empty-state">Requires <code>jit:read</code>.</div>';
        qs('#all-grants-count').textContent = 'n/a';
        return;
      }
      try {
        const tid = TenantCtx.id;
        const { data } = await Api.get('/jit/grants', tid === null ? {} : { tenant_id: tid });
        const grants = data || [];
        qs('#all-grants-count').textContent = `${grants.length} total · ${grants.filter((g) => g.is_active).length} active`;
        if (!grants.length) {
          body.innerHTML = '<div class="empty-state">No grants issued yet.</div>';
          return;
        }
        body.innerHTML = `
          <div class="table-wrap"><table class="data">
            <thead><tr><th>#</th><th>Request</th><th>Grantee</th><th>Asset</th><th>Permissions</th><th>Window</th><th>State</th><th></th></tr></thead>
            <tbody>
              ${grants.map((g) => `
                <tr class="${g.is_active ? 'grant-active' : 'grant-inactive'}">
                  <td class="mono">#${g.id}</td>
                  <td class="mono">#${g.request_id}</td>
                  <td>user #${g.grantee_user_id}</td>
                  <td class="mono">${g.asset_id ? '#' + h(g.asset_id) : '<span class="muted">tenant</span>'}</td>
                  <td class="mono" style="font-size:11px">${h((g.granted_permissions || []).join(', '))}</td>
                  <td>
                    <small class="faint mono">${h(g.valid_from)} → ${h(g.valid_until)}</small><br/>
                    <span class="countdown ${g.is_active ? '' : 'expired'}" data-until="${h(g.valid_until)}" data-active="${g.is_active ? '1' : '0'}"></span>
                  </td>
                  <td>
                    ${g.is_active
                      ? '<span class="badge badge-green">active</span>'
                      : (g.revoked_at ? '<span class="badge badge-red">revoked</span>' : '<span class="badge badge-muted">inactive</span>')}
                  </td>
                  <td class="actions">
                    ${g.is_active && canApprove ? `<button class="btn btn-sm btn-danger" data-revoke="${g.id}">Revoke</button>` : ''}
                  </td>
                </tr>`).join('')}
            </tbody>
          </table></div>`;
        wireGrantButtons(body);
        tickCountdowns(body);
      } catch (err) {
        body.innerHTML = `<div class="error-banner"><span>${h(err.message)}</span></div>`;
      }
    }

    function grantRow(g, compact) {
      const active = g.is_active;
      const now = Date.now();
      const until = window.App.parseISO(g.valid_until);
      const expired = until && until.getTime() <= now;
      return `
        <div class="panel ${active && !expired ? 'grant-active' : 'grant-inactive'}" style="margin-bottom:8px;padding:10px 13px">
          <div style="display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap">
            <div>
              <strong class="mono">Grant #${g.id}</strong>
              <span class="muted" style="font-size:12px"> · asset ${g.asset_id ? '#' + h(g.asset_id) : 'tenant-level'}</span>
              <div class="mono faint" style="font-size:11px">${h((g.granted_permissions || []).join(', '))}</div>
            </div>
            <div style="text-align:right">
              ${active && !expired
                ? `<span class="countdown" data-until="${h(g.valid_until)}" data-active="1"></span><br/><small class="faint">expires ${h(fmtRelative(g.valid_until))}</small>`
                : `<span class="badge ${g.revoked_at ? 'badge-red' : 'badge-muted'}">${g.revoked_at ? 'revoked' : 'expired'}</span><br/><small class="faint">${h(g.valid_until)}</small>`}
               ${active && !expired && g.asset_id && can('asset:jit_access')
                 ? `<br/><button class="btn btn-sm btn-cyan" style="margin-top:5px" data-jit-action="${g.id}" data-asset-id="${g.asset_id}" title="Run a simulated OT action authorized by this active grant">Run OT action ⚡</button>` : ''}
               ${active && !expired && canApprove ? `<br/><button class="btn btn-sm btn-danger" style="margin-top:5px" data-revoke="${g.id}">Revoke</button>` : ''}
             </div>
          </div>
        </div>`;
    }

    function wireGrantButtons(scope) {
      scope.querySelectorAll('[data-revoke]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          if (!confirm('Revoke this grant immediately?')) return;
          try {
            await Api.post(`/jit/grants/${btn.dataset.revoke}/revoke`, { reason: 'revoked from console' });
            toast('Grant revoked.', 'success');
            load();
          } catch (err) { toast(err.message, 'error'); }
        });
      });
      scope.querySelectorAll('[data-jit-action]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            const { data } = await Api.post(`/assets/${btn.dataset.assetId}/jit-action`, {
              action: 'simulated_ot_action',
            });
            toast(`Authorized by grant #${data.grant.id}: ${data.detail}`, 'success', 'OT action executed');
            HashChainBadge.refresh();
            load();
          } catch (err) { toast(err.message, 'error', 'OT action denied'); }
        });
      });
    }

    function tickCountdowns(scope) {
      scope.querySelectorAll('[data-until]').forEach((el) => {
        const until = window.App.parseISO(el.dataset.until);
        if (!until) return;
        const remaining = (until.getTime() - Date.now()) / 1000;
        if (el.dataset.active === '0' || remaining <= 0) {
          el.textContent = 'EXPIRED';
          el.classList.add('expired');
        } else {
          el.textContent = window.App.fmtCountdown(remaining);
        }
      });
    }

    async function submitRequest(e) {
      e.preventDefault();
      const f = e.target;
      const errEl = qs('#req-error');
      errEl.classList.add('hidden');
      const perms = Array.from(f.querySelectorAll('input[name="perm"]:checked')).map((c) => c.value);
      if (!perms.length) {
        errEl.textContent = 'Select at least one permission.';
        errEl.classList.remove('hidden');
        return;
      }
      const until = window.App.fromLocalInput(f.requested_until.value);
      const tid = TenantCtx.id;
      if (tid === null) {
        errEl.textContent = 'Select a tenant context before requesting access.';
        errEl.classList.remove('hidden');
        return;
      }
      try {
        const { data } = await Api.post('/jit/requests', {
          tenant_id: tid,
          asset_id: f.asset_id.value ? parseInt(f.asset_id.value, 10) : null,
          reason: f.reason.value.trim(),
          requested_permissions: perms.join(','),
          requested_until: until,
        });
        toast(`Request #${data.id} submitted for approval.`, 'success', 'JIT request');
        f.reset();
        setDefaultUntil();
        load();
      } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
      }
    }

    function setDefaultUntil() {
      const f = qs('#new-request-form');
      if (!f) return;
      const until = new Date(Date.now() + 2 * 3600 * 1000); // +2h default window
      f.requested_until.value = window.App.toLocalInput(until);
    }

    // Default "requested until" = now + 2 hours.
    setDefaultUntil();

    return stopTimers;
  }

  function statusBadge(status) {
    return {
      pending: 'badge-amber', approved: 'badge-green', rejected: 'badge-red',
      revoked: 'badge-violet', expired: 'badge-muted',
    }[status] || 'badge-muted';
  }

  window.App.registerRoute('jit', '/jit', render);
})();
