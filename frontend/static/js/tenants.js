/* Tenants page: list (members see own), create/update (platform admin only). */
(function () {
  'use strict';
  const { Api, Session, TenantCtx, can, h, qs, toast, Modal, fmtDateTime } = window.App;

  const SECTORS = ['energy', 'water', 'transport'];

  async function render(root) {
    const isPlatform = !!(Session.ctx && Session.ctx.is_platform_admin);
    const canManage = isPlatform && can('tenant:manage');

    root.innerHTML = `
      <div class="page-head">
        <div>
          <h1>Tenants</h1>
          <p class="sub">Industrial tenants with isolated RBAC, fleets, incidents and audit scope.
            ${isPlatform ? '' : 'You see only your own memberships.'}</p>
        </div>
        <div class="page-actions">
          ${canManage ? '<button class="btn btn-primary" id="btn-new-tenant">＋ New tenant</button>' : ''}
          <button class="btn btn-sm" id="tenants-refresh">↻ Refresh</button>
        </div>
      </div>
      ${!canManage && isPlatform ? '<div class="info-banner">Platform context — create/update requires <code>tenant:manage</code>.</div>' : ''}
      <div id="tenants-body"><div class="page-loading"><div class="spinner"></div></div></div>
    `;

    qs('#tenants-refresh').addEventListener('click', load);
    if (canManage) qs('#btn-new-tenant').addEventListener('click', () => openForm(null));
    await load();

    async function load() {
      const body = qs('#tenants-body');
      try {
        const { data: tenants } = await Api.get('/tenants', { include_inactive: 'true' });
        if (!tenants.length) {
          body.innerHTML = '<div class="empty-state"><div class="big">⌂</div>No tenants visible to your account.</div>';
          return;
        }
        body.innerHTML = `
          <div class="grid-3">
            ${tenants.map((t) => tenantCard(t, canManage)).join('')}
          </div>`;
        body.querySelectorAll('[data-edit]').forEach((btn) => {
          btn.addEventListener('click', () => {
            const t = tenants.find((x) => String(x.id) === btn.dataset.edit);
            if (t) openForm(t);
          });
        });
        body.querySelectorAll('[data-select]').forEach((btn) => {
          btn.addEventListener('click', () => {
            TenantCtx.set(parseInt(btn.dataset.select, 10));
            window.App.refreshChrome();
            toast(`Tenant context → ${btn.dataset.name}`, 'success', 'Switched');
          });
        });
      } catch (err) {
        body.innerHTML = `<div class="error-banner"><span>${h(err.message)}</span></div>`;
      }
    }

    function tenantCard(t, manage) {
      const active = t.is_active;
      const current = TenantCtx.id === t.id;
      return `
        <div class="panel" style="margin:0;${current ? 'border-color: var(--amber); box-shadow: 0 0 0 1px rgba(245,158,11,.35);' : ''}">
          <div class="panel-head" style="margin-bottom:8px">
            <h2 style="color:var(--text)">${h(t.name)}</h2>
            <span class="badge ${active ? 'badge-green' : 'badge-red'}">${active ? 'active' : 'disabled'}</span>
          </div>
          <p class="muted" style="margin:2px 0 10px;font-size:12.5px">
            <span class="mono">${h(t.slug)}</span> ·
            <span class="badge badge-cyan badge-plain">${h(t.sector)}</span>
          </p>
          <p class="faint" style="font-size:11.5px;margin:0 0 12px">created ${h(fmtDateTime(t.created_at))}</p>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-sm ${current ? 'btn-primary' : ''}" data-select="${t.id}" data-name="${h(t.name)}">
              ${current ? '✓ Current context' : 'Use as context'}
            </button>
            ${manage ? `<button class="btn btn-sm" data-edit="${t.id}">Edit</button>` : ''}
          </div>
        </div>`;
    }

    function openForm(tenant) {
      const editing = !!tenant;
      Modal.open(`
        <h2>${editing ? 'Edit tenant' : 'Create tenant'} <button class="modal-close" aria-label="Close">×</button></h2>
        <form id="tenant-form">
          <label class="field"><span>Name</span>
            <input name="name" required minlength="2" maxlength="255" value="${h(editing ? tenant.name : '')}" ${editing ? '' : ''} />
          </label>
          <div class="form-row">
            <label class="field"><span>Slug</span>
              <input name="slug" required pattern="[a-z0-9-]+" title="lowercase letters, digits, dashes"
                     value="${h(editing ? tenant.slug : '')}" ${editing ? 'disabled' : ''} placeholder="northgrid" />
            </label>
            <label class="field"><span>Sector</span>
              <select name="sector">
                ${SECTORS.map((s) => `<option value="${s}"${editing && tenant.sector === s ? ' selected' : ''}>${s}</option>`).join('')}
              </select>
            </label>
          </div>
          <label class="field" style="flex-direction:row;align-items:center;gap:8px">
            <input type="checkbox" name="is_active" ${!editing || tenant.is_active ? 'checked' : ''} style="width:auto" />
            <span style="margin:0">Tenant active</span>
          </label>
          <p class="form-error hidden" id="tenant-form-error"></p>
          <div class="modal-actions">
            <button type="button" class="btn" data-modal-close>Cancel</button>
            <button type="submit" class="btn btn-primary">${editing ? 'Save changes' : 'Create tenant'}</button>
          </div>
        </form>
      `);

      qs('#tenant-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const f = e.target;
        const errEl = qs('#tenant-form-error');
        errEl.classList.add('hidden');
        try {
          if (editing) {
            await Api.patch(`/tenants/${tenant.id}`, {
              name: f.name.value.trim(),
              sector: f.sector.value,
              is_active: f.is_active.checked,
            });
            toast('Tenant updated.', 'success');
          } else {
            const { data } = await Api.post('/tenants', {
              name: f.name.value.trim(),
              slug: f.slug.value.trim(),
              sector: f.sector.value,
              is_active: f.is_active.checked,
            });
            toast(`Tenant “${data.name}” created.`, 'success');
          }
          Modal.close();
          // Platform admin tenant list may have changed → refresh chrome too.
          await window.App.Session.refresh();
          await window.App.refreshChrome();
          load();
        } catch (err) {
          errEl.textContent = err.message;
          errEl.classList.remove('hidden');
        }
      });
    }
  }

  window.App.registerRoute('tenants', '/tenants', render);
})();
