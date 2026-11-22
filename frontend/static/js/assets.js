/* OT Fleet assets: status grid, CRUD (asset:write), active JIT grants lookup. */
(function () {
  'use strict';
  const { Api, TenantCtx, can, h, qs, toast, Modal, fmtRelative, fmtDateTime } = window.App;

  const TYPES = ['PLC', 'RTU', 'HMI', 'SENSOR', 'CONTROLLER'];
  const STATUSES = ['online', 'offline', 'maintenance', 'alert'];

  const STATUS_BADGE = { online: 'badge-green', offline: 'badge-muted', maintenance: 'badge-amber', alert: 'badge-red' };

  async function render(root) {
    const canWrite = can('asset:write');
    const canRead = can('asset:read');

    root.innerHTML = `
      <div class="page-head">
        <div>
          <h1>OT Fleet <span class="badge badge-cyan badge-plain">${h((TenantCtx.current() || {}).name || 'all tenants')}</span></h1>
          <p class="sub">Industrial control assets (PLC · RTU · HMI · SENSOR · CONTROLLER) with tenant row-level isolation.</p>
        </div>
        <div class="page-actions">
          ${canWrite ? '<button class="btn btn-primary" id="btn-new-asset">＋ New asset</button>' : ''}
          <button class="btn btn-sm" id="assets-refresh">↻ Refresh</button>
        </div>
      </div>

      <div class="filter-bar panel" style="padding:12px 14px">
        <label class="field"><span>Status</span>
          <select id="f-status"><option value="">all</option>${STATUSES.map((s) => `<option>${s}</option>`).join('')}</select>
        </label>
        <label class="field"><span>Type</span>
          <select id="f-type"><option value="">all</option>${TYPES.map((t) => `<option>${t}</option>`).join('')}</select>
        </label>
        <label class="field grow-2"><span>Search tag / name / site</span>
          <input id="f-search" placeholder="PLC-001, substation…" />
        </label>
        <div class="kpi" style="min-width:130px;flex:0 0 auto">
          <div class="kpi-label">Assets</div>
          <div class="kpi-value" id="asset-count" style="font-size:22px">…</div>
        </div>
      </div>

      <div id="assets-body"><div class="page-loading"><div class="spinner"></div></div></div>
    `;

    qs('#assets-refresh').addEventListener('click', load);
    qs('#f-status').addEventListener('change', load);
    qs('#f-type').addEventListener('change', load);
    qs('#f-search').addEventListener('input', debounce(load, 250));
    if (canWrite) qs('#btn-new-asset').addEventListener('click', () => openForm(null));

    let allAssets = [];
    await load();

    async function load() {
      const body = qs('#assets-body');
      if (!canRead) {
        body.innerHTML = '<div class="empty-state"><div class="big">🔒</div>Requires <code>asset:read</code> in this tenant.</div>';
        qs('#asset-count').textContent = '—';
        return;
      }
      try {
        const tid = TenantCtx.id;
        const { data } = await Api.get('/assets', tid === null ? {} : { tenant_id: tid });
        allAssets = data || [];
        applyFilters();
      } catch (err) {
        body.innerHTML = `<div class="error-banner"><span>${h(err.message)}</span></div>`;
      }
    }

    function applyFilters() {
      const status = qs('#f-status').value;
      const type = qs('#f-type').value;
      const q = qs('#f-search').value.trim().toLowerCase();
      const rows = allAssets.filter((a) =>
        (!status || a.status === status) &&
        (!type || a.type === type) &&
        (!q || `${a.asset_tag} ${a.name} ${a.site || ''}`.toLowerCase().includes(q))
      );
      qs('#asset-count').textContent = rows.length;
      renderTable(rows);
    }

    function renderTable(rows) {
      const body = qs('#assets-body');
      if (!rows.length) {
        body.innerHTML = '<div class="empty-state"><div class="big">⛭</div>No assets match the current filter.</div>';
        return;
      }
      body.innerHTML = `
        <div class="table-wrap"><table class="data">
          <thead>
            <tr>
              <th>Tag</th><th>Name</th><th>Type</th><th>Site</th><th>Status</th><th>Last seen</th>
              <th style="text-align:right">JIT / Actions</th>
            </tr>
          </thead>
          <tbody>
            ${rows.map((a) => `
              <tr class="${a.status === 'alert' ? 'row-overdue' : ''}" data-asset-row="${a.id}">
                <td class="mono"><strong>${h(a.asset_tag)}</strong><br/><small class="faint">#${a.id} · t${a.tenant_id}</small></td>
                <td>${h(a.name)}</td>
                <td><span class="badge badge-cyan badge-plain">${h(a.type)}</span></td>
                <td class="muted">${h(a.site || '—')}</td>
                <td><span class="badge ${STATUS_BADGE[a.status] || 'badge-muted'}">${h(a.status)}</span></td>
                <td class="muted nowrap" title="${h(fmtDateTime(a.last_seen))}">${h(fmtRelative(a.last_seen))}</td>
                <td class="actions">
                  ${can('jit:read') ? `<button class="btn btn-sm btn-ghost" data-jit="${a.id}" title="Active JIT grants on this asset">JIT ⏱</button>` : ''}
                  ${canWrite ? `<button class="btn btn-sm" data-edit="${a.id}">Edit</button>` : ''}
                  ${canWrite ? `<button class="btn btn-sm btn-danger" data-del="${a.id}">Del</button>` : ''}
                </td>
              </tr>`).join('')}
          </tbody>
        </table></div>`;

      body.querySelectorAll('[data-jit]').forEach((btn) => {
        btn.addEventListener('click', () => showJit(parseInt(btn.dataset.jit, 10), rows));
      });
      body.querySelectorAll('[data-edit]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const a = rows.find((x) => String(x.id) === btn.dataset.edit);
          if (a) openForm(a);
        });
      });
      body.querySelectorAll('[data-del]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const a = rows.find((x) => String(x.id) === btn.dataset.del);
          if (!a) return;
          if (!confirm(`Delete asset ${a.asset_tag}? This cannot be undone.`)) return;
          try {
            await Api.del(`/assets/${a.id}`);
            toast(`Asset ${a.asset_tag} deleted.`, 'success');
            load();
          } catch (err) { toast(err.message, 'error'); }
        });
      });
    }

    async function showJit(assetId, rows) {
      const asset = rows.find((x) => x.id === assetId);
      Modal.open(`
        <h2>Active JIT grants · ${h(asset ? asset.asset_tag : '#' + assetId)}
          <button class="modal-close" aria-label="Close">×</button></h2>
        <div id="jit-detail"><div class="page-loading"><div class="spinner"></div></div></div>
        <div class="modal-actions"><button class="btn" data-modal-close>Close</button></div>
      `);
      try {
        const { data } = await Api.get(`/assets/${assetId}/jit-active`);
        const host = qs('#jit-detail');
        if (!data || !data.length) {
          host.innerHTML = '<div class="empty-state">No active JIT grants on this asset.</div>';
          return;
        }
        host.innerHTML = `
          <div class="table-wrap"><table class="data">
            <thead><tr><th>Grantee</th><th>Permissions</th><th>Valid until</th><th></th></tr></thead>
            <tbody>
              ${data.map((g) => `
                <tr class="grant-active">
                  <td>user #${g.grantee_user_id}</td>
                  <td class="mono" style="font-size:11px">${h((g.granted_permissions || []).join(', '))}</td>
                  <td><span class="countdown" data-until="${h(g.valid_until)}"></span><br/><small class="faint">${h(g.valid_until)}</small></td>
                  <td></td>
                </tr>`).join('')}
            </tbody>
          </table></div>`;
        const stop = window.App.TimerWidget.tick(host);
        // clean up when modal closes
        const observer = setInterval(() => {
          if (qs('#modal-host').classList.contains('hidden')) { stop(); clearInterval(observer); }
        }, 1000);
      } catch (err) {
        qs('#jit-detail').innerHTML = `<div class="error-banner"><span>${h(err.message)}</span></div>`;
      }
    }

    function openForm(asset) {
      const editing = !!asset;
      const tid = TenantCtx.id;
      Modal.open(`
        <h2>${editing ? 'Edit asset' : 'Create asset'} <button class="modal-close" aria-label="Close">×</button></h2>
        <form id="asset-form">
          <div class="form-row">
            <label class="field"><span>Asset tag</span>
              <input name="asset_tag" required maxlength="64" value="${h(editing ? asset.asset_tag : '')}" placeholder="PLC-001" />
            </label>
            <label class="field"><span>Type</span>
              <select name="type">${TYPES.map((t) => `<option${editing && asset.type === t ? ' selected' : ''}>${t}</option>`).join('')}</select>
            </label>
          </div>
          <label class="field"><span>Name</span>
            <input name="name" required maxlength="255" value="${h(editing ? asset.name : '')}" />
          </label>
          <div class="form-row">
            <label class="field"><span>Site</span>
              <input name="site" maxlength="255" value="${h(editing ? asset.site || '' : '')}" placeholder="North Substation" />
            </label>
            <label class="field"><span>Status</span>
              <select name="status">${STATUSES.map((s) => `<option${editing && asset.status === s ? ' selected' : ''}>${s}</option>`).join('')}</select>
            </label>
          </div>
          ${editing ? '' : `
          <label class="field"><span>Tenant</span>
            <select name="tenant_id" ${tid !== null ? 'disabled' : ''}>
              ${TenantCtx.list().map((t) => `<option value="${t.id}"${tid === t.id ? ' selected' : ''}>${h(t.name)}</option>`).join('')}
            </select>
          </label>`}
          <p class="form-error hidden" id="asset-form-error"></p>
          <div class="modal-actions">
            <button type="button" class="btn" data-modal-close>Cancel</button>
            <button type="submit" class="btn btn-primary">${editing ? 'Save' : 'Create'}</button>
          </div>
        </form>
      `);

      qs('#asset-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const f = e.target;
        const errEl = qs('#asset-form-error');
        errEl.classList.add('hidden');
        try {
          if (editing) {
            await Api.patch(`/assets/${asset.id}`, {
              asset_tag: f.asset_tag.value.trim(),
              name: f.name.value.trim(),
              type: f.type.value,
              site: f.site.value.trim() || null,
              status: f.status.value,
            });
            toast('Asset updated.', 'success');
          } else {
            const tenantId = tid !== null ? tid : parseInt(f.tenant_id.value, 10);
            await Api.post('/assets', {
              tenant_id: tenantId,
              asset_tag: f.asset_tag.value.trim(),
              name: f.name.value.trim(),
              type: f.type.value,
              site: f.site.value.trim() || null,
              status: f.status.value,
            });
            toast('Asset created.', 'success');
          }
          Modal.close();
          load();
        } catch (err) {
          errEl.textContent = err.message;
          errEl.classList.remove('hidden');
        }
      });
    }
  }

  function debounce(fn, ms) {
    let t;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }

  window.App.registerRoute('assets', '/assets', render);
})();
