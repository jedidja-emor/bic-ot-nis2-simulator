/* Login page: POST /auth/login + static demo credential chips. */
(function () {
  'use strict';
  const { Api, Session, h, qs, toast } = window.App;

  // Intentionally public simulator accounts (mirror backend/app/seed.py).
  // Never use these demo credentials in a production deployment.
  const DEMO_ACCOUNTS = [
    { email: 'platform@beeincontrol.io', password: 'Platform123!', role: 'platform_admin', tenant: null },
    { email: 'admin@northgrid.io', password: 'NorthGrid123!', role: 'tenant_admin', tenant: 'northgrid' },
    { email: 'engineer@northgrid.io', password: 'NorthGrid123!', role: 'site_engineer', tenant: 'northgrid' },
    { email: 'officer@northgrid.io', password: 'NorthGrid123!', role: 'security_officer', tenant: 'northgrid' },
    { email: 'viewer@northgrid.io', password: 'NorthGrid123!', role: 'viewer', tenant: 'northgrid' },
    { email: 'vendor@acme-ot.com', password: 'Vendor123!', role: 'vendor_remote', tenant: 'northgrid' },
    { email: 'admin@aquaflow.io', password: 'AquaFlow123!', role: 'tenant_admin', tenant: 'aquaflow' },
    { email: 'officer@aquaflow.io', password: 'AquaFlow123!', role: 'security_officer', tenant: 'aquaflow' },
    { email: 'vendor@aqua-ot.com', password: 'Vendor123!', role: 'vendor_remote', tenant: 'aquaflow' },
    { email: 'admin@transitrail.io', password: 'TransitRail123!', role: 'tenant_admin', tenant: 'transitrail' },
    { email: 'engineer@transitrail.io', password: 'TransitRail123!', role: 'site_engineer', tenant: 'transitrail' },
    { email: 'vendor@rail-ot.com', password: 'Vendor123!', role: 'vendor_remote', tenant: 'transitrail' },
  ];

  const ROLE_BADGE = {
    platform_admin: 'platform',
    tenant_admin: 'admin',
    site_engineer: 'engineer',
    security_officer: 'officer',
    viewer: 'viewer',
    vendor_remote: 'vendor',
  };

  function renderDemoCredentials() {
    const host = qs('#demo-list');
    if (!host) return;
    if (!DEMO_ACCOUNTS.length) {
      host.innerHTML = '<p class="muted">No demo accounts configured.</p>';
      return;
    }
    host.innerHTML = DEMO_ACCOUNTS.map((c) => `
      <button type="button" class="demo-card" data-email="${h(c.email)}" data-password="${h(c.password)}">
        <span>
          <strong>${h(c.email)}</strong>
          <small>${h(c.password)}</small>
        </span>
        <span class="demo-role">${h(ROLE_BADGE[c.role] || c.role)}${c.tenant ? ' · ' + h(c.tenant) : ''}</span>
      </button>
    `).join('');

    host.querySelectorAll('.demo-card').forEach((card) => {
      card.addEventListener('click', () => {
        const form = qs('#login-form');
        form.email.value = card.dataset.email;
        form.password.value = card.dataset.password;
        form.requestSubmit();
      });
    });
  }

  async function submitLogin(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const errorEl = qs('#login-error');
    const submit = qs('#login-submit');
    errorEl.classList.add('hidden');
    submit.disabled = true;
    submit.textContent = 'Authenticating…';

    try {
      const { data } = await Api.post('/auth/login', {
        email: form.email.value.trim(),
        password: form.password.value,
      });
      Session.save(data.access_token, data.user);
      toast(`Welcome, ${(data.user && (data.user.full_name || data.user.email)) || 'operator'}.`, 'success', 'Authenticated');
      window.App.showApp();
    } catch (err) {
      errorEl.textContent = err.message || 'Login failed';
      errorEl.classList.remove('hidden');
    } finally {
      submit.disabled = false;
      submit.textContent = 'Sign in';
    }
  }

  function initLogin() {
    const form = qs('#login-form');
    if (form && !form.dataset.bound) {
      form.dataset.bound = '1';
      form.addEventListener('submit', submitLogin);
    }
    const refresh = qs('#seed-refresh');
    if (refresh && !refresh.dataset.bound) {
      refresh.dataset.bound = '1';
      refresh.addEventListener('click', renderDemoCredentials);
    }
    renderDemoCredentials();
    const first = form && form.querySelector('input[name="email"]');
    if (first) first.focus();
  }

  window.BeeAuth = { initLogin };
})();
