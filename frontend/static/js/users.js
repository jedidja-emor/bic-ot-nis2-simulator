/* Users & Roles: user CRUD, role catalogue, tenant-scoped role assignments. */
(function () {
  'use strict';
  const { Api, Session, TenantCtx, can, h, qs, toast, Modal, fmtDateTime, fmtRelative } = window.App;

  let cache = { users: [], roles: [], permissions: [] };

  async function render(root) {
    const isPlatform = !!(Session.ctx && Session.ctx.is_platform_admin);
    const canManage = can('user:manage');

    root.innerHTML = `
      <div class="page-head">
        <div>
          <h1>Users &amp; Roles</h1>
          <p class="sub">Tenant-scoped RBAC assignments. Effective permissions shown per role; the server enforces grants on every API call.</p>
        </div>
        <div class="page-actions">
          ${canManage ? '<button class="btn btn-primary" id="btn-new-user">＋ New user</button>' : ''}
          <button class="btn btn-sm" id="users-refresh">↻ Refresh</button>
        </div>
      </div>

      ${canManage ? '' : '<div class="warn-banner">Read-only: your roles lack <code>user:manage</code> in this tenant context.</div>'}

      <div class="grid-2">
        <section class="panel">
          <div class="panel-head">
            <h2>Users ${TenantCtx.id ? `· ${h((TenantCtx.current() || {}).name || '')}` : ''}</h2>
            <label style="display:flex;align-items:center;gap:6px;font-size:12px">
              <input type="checkbox" id="show-inactive" /> show inactive
            </label>
          </div>
          <div id="users-body"><div class="page-loading"><div class="spinner"></div></div></div>
        </section>

        <div>
          <section class="panel">
            <div class="panel-head"><h2>Role catalogue</h2><span class="pill" id="roles-count">—</span></div>
            <div id="roles-body"><div class="page-loading"><div class="spinner"></div></div></div>
          </section>

          ${canManage ? `
          <section class="panel">
            <div class="panel-head"><h2>Assign role (tenant-scoped)</h2></div>
            <form id="assign-form">
              <div class="form-row">
                <label class="field"><span>User</span><select name="user_id" id="assign-user" required></select></label>
                <label class="field"><span>Role</span><select name="role_id" id="assign-role" required></select></label>
              </div>
              <div class="form-row">
                <label class="field"><span>Tenant</span><select name="tenant_id" id="assign-tenant" required></select></label>
                <label class="field"><span>Expires (optional)</span><input type="datetime-local" name="expires_at" /></label>
              </div>
              <p class="form-error hidden" id="assign-error"></p>
              <button class="btn btn-cyan btn-block" type="submit">Assign role</button>
            </form>
          </section>` : ''}
        </div>
      </div>
    `;

    qs('#users-refresh').addEventListener('click', load);
    qs('#show-inactive').addEventListener('change', load);
    if (canManage) qs('#btn-new-user').addEventListener('click', () => openUserForm(null));
    if (canManage) qs('#assign-form').addEventListener('submit', submitAssign);
    await load();

    async function load() {
      const tid = TenantCtx.id;
      const tQuery = tid === null ? {} : { tenant_id: tid };

      // Roles catalogue (also needed to power role switcher map).
      if (can('role:manage') || canManage) {
        try {
          const { data: roles } = await Api.get('/roles');
          cache.roles = roles || [];
        } catch { cache.roles = []; }
        try {
          const { data: perms } = await Api.get('/permissions');
          cache.permissions = perms || [];
        } catch { cache.permissions = []; }
      }

      // Users
      const usersBody = qs('#users-body');
      if (!canManage) {
        usersBody.innerHTML = '<div class="empty-state">Requires <code>user:manage</code>.</div>';
      } else {
        try {
          const includeInactive = qs('#show-inactive').checked ? 'true' : '';
          const { data: users } = await Api.get('/users', { ...tQuery, include_inactive: includeInactive });
          cache.users = users || [];
          renderUsers(cache.users);
        } catch (err) {
          usersBody.innerHTML = `<div class="error-banner"><span>${h(err.message)}</span></div>`;
        }
      }

      // Roles panel
      const rolesBody = qs('#roles-body');
      if (!cache.roles.length) {
        rolesBody.innerHTML = '<div class="empty-state">Role catalogue unavailable (requires <code>role:manage</code> or <code>user:manage</code>).</div>';
        qs('#roles-count').textContent = 'n/a';
      } else {
        qs('#roles-count').textContent = `${cache.roles.length} roles · ${cache.permissions.length} perms`;
        rolesBody.innerHTML = `
          <div class="table-wrap"><table class="data">
            <thead><tr><th>Role</th><th>Scope</th><th>Permissions</th></tr></thead>
            <tbody>
              ${cache.roles.map((r) => `
                <tr>
                  <td><strong>${h(r.name)}</strong>${r.is_system ? ' <span class="badge badge-muted badge-plain">sys</span>' : ''}</td>
                  <td><span class="badge ${r.scope === 'global' ? 'badge-violet' : 'badge-cyan'} badge-plain">${h(r.scope)}</span></td>
                  <td style="font-size:11px" class="mono muted">${h((r.permissions || []).join(', ') || '—')}</td>
                </tr>`).join('')}
            </tbody>
          </table></div>`;
      }

      // Assign form dropdowns
      if (canManage) {
        const userSel = qs('#assign-user');
        const roleSel = qs('#assign-role');
        const tenantSel = qs('#assign-tenant');
        if (userSel) {
          userSel.innerHTML = cache.users.map((u) => `<option value="${u.id}">${h(u.full_name)} · ${h(u.email)}</option>`).join('')
            || '<option value="" disabled>No users in context</option>';
        }
        if (roleSel) {
          const tenantRoles = cache.roles.filter((r) => r.scope === 'tenant');
          roleSel.innerHTML = (tenantRoles.length ? tenantRoles : cache.roles)
            .map((r) => `<option value="${r.id}">${h(r.name)} (${h(r.scope)})</option>`).join('');
        }
        if (tenantSel) {
          const tenants = TenantCtx.list();
          tenantSel.innerHTML = tenants.map((t) =>
            `<option value="${t.id}"${TenantCtx.id === t.id ? ' selected' : ''}>${h(t.name)}</option>`).join('');
          if (isPlatform && !tenants.length) {
            // Platform admins pick from all tenants via /tenants.
            Api.get('/tenants').then(({ data }) => {
              tenantSel.innerHTML = (data || []).map((t) => `<option value="${t.id}">${h(t.name)}</option>`).join('');
            }).catch(() => {});
          }
        }
      }
    }

    function renderUsers(users) {
      const body = qs('#users-body');
      if (!users.length) {
        body.innerHTML = '<div class="empty-state"><div class="big">👤</div>No users in this tenant context.</div>';
        return;
      }
      body.innerHTML = `
        <div class="table-wrap"><table class="data">
          <thead><tr><th>User</th><th>Roles (tenant)</th><th>Flags</th><th></th></tr></thead>
          <tbody>
            ${users.map((u) => `
              <tr class="${u.is_active ? '' : 'grant-inactive'}">
                <td>
                  <strong>${h(u.full_name)}</strong><br/>
                  <small class="mono muted">${h(u.email)}</small>
                </td>
                <td>
                  ${(u.roles || []).map((r) => `
                    <span class="badge ${r.scope === 'global' ? 'badge-violet' : 'badge-cyan'} badge-plain"
                          title="${h(r.expires_at ? 'expires ' + r.expires_at : 'no expiry')}" style="margin:1px 3px 1px 0">
                      ${h(r.name)}${r.tenant_id ? ' @' + h(r.tenant_id) : ''}
                      ${r.user_role_id && canManage ? `<a href="#" data-unassign="${r.user_role_id}" title="Remove assignment" style="margin-left:5px;color:var(--red)">×</a>` : ''}
                    </span>`).join('') || '<span class="muted">—</span>'}
                </td>
                <td>
                  ${u.is_vendor ? '<span class="badge badge-amber">vendor</span>' : ''}
                  ${u.is_active ? '<span class="badge badge-green">active</span>' : '<span class="badge badge-red">disabled</span>'}
                  ${u.tenant_id === null ? '<span class="badge badge-violet">global</span>' : ''}
                </td>
                <td class="actions">
                  ${canManage ? `<button class="btn btn-sm" data-edit-user="${u.id}">Edit</button>` : ''}
                  ${canManage && u.is_active ? `<button class="btn btn-sm btn-danger" data-disable-user="${u.id}">Disable</button>` : ''}
                </td>
              </tr>`).join('')}
          </tbody>
        </table></div>`;

      body.querySelectorAll('[data-edit-user]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const u = users.find((x) => String(x.id) === btn.dataset.editUser);
          if (u) openUserForm(u);
        });
      });
      body.querySelectorAll('[data-disable-user]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          if (!confirm('Deactivate this user?')) return;
          try {
            await Api.del(`/users/${btn.dataset.disableUser}`);
            toast('User deactivated.', 'success');
            load();
          } catch (err) { toast(err.message, 'error'); }
        });
      });
      body.querySelectorAll('[data-unassign]').forEach((a) => {
        a.addEventListener('click', async (e) => {
          e.preventDefault();
          if (!confirm('Remove this role assignment?')) return;
          try {
            await Api.del(`/user-roles/${a.dataset.unassign}`);
            toast('Role assignment removed.', 'success');
            await Session.refresh();
            window.App.refreshChrome();
            load();
          } catch (err) { toast(err.message, 'error'); }
        });
      });
    }

    function openUserForm(user) {
      const editing = !!user;
      const tenants = TenantCtx.list();
      Modal.open(`
        <h2>${editing ? 'Edit user' : 'Create user'} <button class="modal-close" aria-label="Close">×</button></h2>
        <form id="user-form">
          <label class="field"><span>Email</span>
            <input type="email" name="email" ${editing ? 'readonly' : 'required'} value="${h(editing ? user.email : '')}" />
          </label>
          <label class="field"><span>Full name</span>
            <input name="full_name" required value="${h(editing ? user.full_name : '')}" />
          </label>
          <label class="field"><span>${editing ? 'New password (blank = keep)' : 'Password'}</span>
            <input type="password" name="password" ${editing ? '' : 'required minlength="6"'} placeholder="${editing ? 'unchanged' : 'min 6 chars'}" />
          </label>
          <div class="form-row">
            <label class="field"><span>Tenant</span>
              <select name="tenant_id" ${editing ? 'disabled' : ''}>
                <option value="">— global / none —</option>
                ${tenants.map((t) => `<option value="${t.id}"${TenantCtx.id === t.id ? ' selected' : ''}>${h(t.name)}</option>`).join('')}
              </select>
            </label>
            <label class="field"><span>Initial role (optional)</span>
              <select name="role_id">
                <option value="">— none —</option>
                ${cache.roles.map((r) => `<option value="${r.id}">${h(r.name)}</option>`).join('')}
              </select>
            </label>
          </div>
          <div class="form-row">
            <label class="field" style="flex-direction:row;align-items:center;gap:8px">
              <input type="checkbox" name="is_vendor" ${editing && user.is_vendor ? 'checked' : ''} style="width:auto" />
              <span style="margin:0">Vendor user</span>
            </label>
            <label class="field" style="flex-direction:row;align-items:center;gap:8px">
              <input type="checkbox" name="is_active" ${!editing || user.is_active ? 'checked' : ''} style="width:auto" />
              <span style="margin:0">Active</span>
            </label>
          </div>
          <p class="form-error hidden" id="user-form-error"></p>
          <div class="modal-actions">
            <button type="button" class="btn" data-modal-close>Cancel</button>
            <button type="submit" class="btn btn-primary">${editing ? 'Save' : 'Create user'}</button>
          </div>
        </form>
      `);

      qs('#user-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const f = e.target;
        const errEl = qs('#user-form-error');
        errEl.classList.add('hidden');
        try {
          if (editing) {
            const body = {
              full_name: f.full_name.value.trim(),
              is_active: f.is_active.checked,
              is_vendor: f.is_vendor.checked,
            };
            if (f.password.value) body.password = f.password.value;
            await Api.patch(`/users/${user.id}`, body);
            toast('User updated.', 'success');
          } else {
            const body = {
              email: f.email.value.trim(),
              full_name: f.full_name.value.trim(),
              password: f.password.value,
              is_vendor: f.is_vendor.checked,
              is_active: f.is_active.checked,
            };
            if (f.tenant_id.value) body.tenant_id = parseInt(f.tenant_id.value, 10);
            if (f.role_id.value) body.role_id = parseInt(f.role_id.value, 10);
            await Api.post('/users', body);
            toast('User created.', 'success');
          }
          Modal.close();
          load();
        } catch (err) {
          errEl.textContent = err.message;
          errEl.classList.remove('hidden');
        }
      });
    }

    async function submitAssign(e) {
      e.preventDefault();
      const f = e.target;
      const errEl = qs('#assign-error');
      errEl.classList.add('hidden');
      try {
        const body = {
          user_id: parseInt(f.user_id.value, 10),
          role_id: parseInt(f.role_id.value, 10),
          tenant_id: parseInt(f.tenant_id.value, 10),
        };
        if (f.expires_at.value) body.expires_at = window.App.fromLocalInput(f.expires_at.value);
        await Api.post('/user-roles', body);
        toast('Role assigned.', 'success');
        await Session.refresh();
        window.App.refreshChrome();
        load();
      } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
      }
    }
  }

  window.App.registerRoute('users', '/users', render);
})();
