/* =========================================================================
   BeeInControl SPA core
   - ApiClient   : fetch wrapper with Bearer JWT + 401 handling
   - Session     : token + /auth/me context in sessionStorage
   - TenantCtx   : current tenant selector (sessionStorage)
   - RoleCtx     : UI role context selector (server still enforces union)
   - can()       : permission-aware UI guard (PermissionGuard)
   - TimerWidget : live 24h/72h NIS2 countdowns
   - HashChainBadge : audit chain status
   - Router      : history-based SPA routing
   ========================================================================= */
(function () {
  'use strict';

  const API_BASE = '/api/v1';
  const TOKEN_KEY = 'bic_token';
  const CTX_KEY = 'bic_ctx';
  const TENANT_KEY = 'bic_tenant';
  const ROLE_KEY = 'bic_role';

  /* ------------------------------ helpers ------------------------------ */
  function h(value) {
    if (value === null || value === undefined) return '';
    return String(value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function qs(sel, root) { return (root || document).querySelector(sel); }
  function qsa(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

  function parseISO(text) {
    if (!text) return null;
    let t = String(text).trim();
    if (t.endsWith('Z')) t = t.slice(0, -1) + '+00:00';
    const d = new Date(t);
    return isNaN(d.getTime()) ? null : d;
  }

  /** Format seconds as HH:MM:SS (or DDd HH:MM:SS for long spans). */
  function fmtCountdown(seconds) {
    const s = Math.max(0, Math.floor(seconds || 0));
    const days = Math.floor(s / 86400);
    const hrs = Math.floor((s % 86400) / 3600);
    const min = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    const pad = (n) => String(n).padStart(2, '0');
    const base = `${pad(hrs)}:${pad(min)}:${pad(sec)}`;
    return days > 0 ? `${days}d ${base}` : base;
  }

  function fmtDateTime(text) {
    const d = parseISO(text);
    if (!d) return '—';
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC');
  }

  function fmtRelative(text) {
    const d = parseISO(text);
    if (!d) return '—';
    const diff = Date.now() - d.getTime();
    const abs = Math.abs(diff);
    const mins = Math.round(abs / 60000);
    const suffix = diff >= 0 ? 'ago' : 'from now';
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ${suffix}`;
    const hrs = Math.round(mins / 60);
    if (hrs < 48) return `${hrs}h ${suffix}`;
    return `${Math.round(hrs / 24)}d ${suffix}`;
  }

  /** datetime-local input value (local time) from ISO string or Date. */
  function toLocalInput(date) {
    const d = date instanceof Date ? date : (parseISO(date) || new Date());
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  /** Convert datetime-local input value to UTC ISO string (…Z). */
  function fromLocalInput(value) {
    if (!value) return null;
    const d = new Date(value);
    if (isNaN(d.getTime())) return null;
    return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
  }

  function toast(message, kind = 'info', title = '') {
    const host = qs('#toast-host');
    if (!host) return;
    const el = document.createElement('div');
    el.className = `toast ${kind}`;
    el.innerHTML = `${title ? `<strong>${h(title)}</strong>` : ''}<span>${h(message)}</span>`;
    host.appendChild(el);
    setTimeout(() => {
      el.style.transition = 'opacity .3s, transform .3s';
      el.style.opacity = '0';
      el.style.transform = 'translateX(30px)';
      setTimeout(() => el.remove(), 320);
    }, kind === 'error' ? 5200 : 3400);
  }

  /* ------------------------------ modal ------------------------------ */
  const Modal = {
    open(html) {
      const host = qs('#modal-host');
      const card = qs('#modal-card');
      card.innerHTML = html;
      host.classList.remove('hidden');
      host.onclick = (e) => {
        if (e.target.hasAttribute('data-modal-close') || e.target.classList.contains('modal-close')) {
          Modal.close();
        }
      };
      const first = card.querySelector('input, select, textarea, button');
      if (first) first.focus();
    },
    close() {
      qs('#modal-host').classList.add('hidden');
      qs('#modal-card').innerHTML = '';
    },
  };

  /* ------------------------------ ApiClient ------------------------------ */
  const Api = {
    async request(path, opts = {}) {
      const { method = 'GET', body, query, raw = false } = opts;
      const url = new URL(API_BASE + path, window.location.origin);
      if (query) {
        Object.entries(query).forEach(([k, v]) => {
          if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
        });
      }
      const headers = { Accept: 'application/json' };
      const token = sessionStorage.getItem(TOKEN_KEY);
      if (token) headers.Authorization = `Bearer ${token}`;
      if (body !== undefined) headers['Content-Type'] = 'application/json';

      let res;
      try {
        res = await fetch(url.toString(), {
          method,
          headers,
          body: body !== undefined ? JSON.stringify(body) : undefined,
        });
      } catch (err) {
        const e = new Error('Cannot reach the BeeInControl API — is the backend running?');
        e.status = 0;
        throw e;
      }

      if (res.status === 401 && path !== '/auth/login') {
        Session.clear();
        if (!location.pathname.startsWith('/login')) {
          navigate('/login', { replace: true });
        }
        const e = new Error('Session expired — please sign in again.');
        e.status = 401;
        throw e;
      }

      if (raw) return res;

      const text = await res.text();
      let data = null;
      if (text) {
        try { data = JSON.parse(text); } catch { data = text; }
      }
      if (!res.ok) {
        let detail = (data && data.detail) ? data.detail : (data || res.statusText);
        if (Array.isArray(detail)) {
          detail = detail.map((d) => d.msg || JSON.stringify(d)).join('; ');
        }
        const e = new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
        e.status = res.status;
        e.data = data;
        throw e;
      }
      return { data, status: res.status, headers: res.headers };
    },
    get(path, query, opts) { return this.request(path, { ...opts, method: 'GET', query }); },
    post(path, body, opts) { return this.request(path, { ...opts, method: 'POST', body }); },
    patch(path, body, opts) { return this.request(path, { ...opts, method: 'PATCH', body }); },
    del(path, opts) { return this.request(path, { ...opts, method: 'DELETE' }); },
  };

  /* ------------------------------ Session ------------------------------ */
  const Session = {
    get token() { return sessionStorage.getItem(TOKEN_KEY); },
    get ctx() {
      try { return JSON.parse(sessionStorage.getItem(CTX_KEY) || 'null'); }
      catch { return null; }
    },
    save(token, ctx) {
      sessionStorage.setItem(TOKEN_KEY, token);
      sessionStorage.setItem(CTX_KEY, JSON.stringify(ctx));
    },
    setCtx(ctx) { sessionStorage.setItem(CTX_KEY, JSON.stringify(ctx)); },
    clear() {
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(CTX_KEY);
      sessionStorage.removeItem(TENANT_KEY);
      sessionStorage.removeItem(ROLE_KEY);
    },
    async refresh() {
      const { data } = await Api.get('/auth/me');
      Session.setCtx(data);
      return data;
    },
  };

  /* ------------------------------ Tenant context ------------------------------ */
  const TenantCtx = {
    get id() {
      const raw = sessionStorage.getItem(TENANT_KEY);
      if (raw === '' || raw === 'all') return null; // "all tenants" (platform)
      const n = parseInt(raw, 10);
      return Number.isFinite(n) ? n : null;
    },
    set(id) {
      sessionStorage.setItem(TENANT_KEY, id === null || id === undefined ? 'all' : String(id));
      window.dispatchEvent(new CustomEvent('tenant-changed', { detail: { tenantId: TenantCtx.id } }));
    },
    /** Tenants available to the current user (from /auth/me). */
    list() {
      const ctx = Session.ctx;
      return (ctx && ctx.tenants) || [];
    },
    current() {
      const id = TenantCtx.id;
      if (id === null) return null;
      return TenantCtx.list().find((t) => t.id === id) || null;
    },
    /** Ensure a sensible selection after login / context refresh. */
    ensureValid() {
      const tenants = TenantCtx.list();
      const id = TenantCtx.id;
      if (id !== null && tenants.some((t) => t.id === id)) return id;
      if (tenants.length > 0) {
        sessionStorage.setItem(TENANT_KEY, String(tenants[0].id));
        return tenants[0].id;
      }
      sessionStorage.setItem(TENANT_KEY, 'all');
      return null;
    },
    /** Query params for tenant-scoped list endpoints (null omits → backend scope). */
    query() {
      const id = TenantCtx.id;
      return id === null ? {} : { tenant_id: id };
    },
  };

  /* ------------------------------ Role context (UI) ------------------------------ */
  const RoleCtx = {
    /** 'effective' | role name */
    get selected() { return sessionStorage.getItem(ROLE_KEY) || 'effective'; },
    set(name) {
      sessionStorage.setItem(ROLE_KEY, name || 'effective');
      window.dispatchEvent(new CustomEvent('role-changed', { detail: { role: RoleCtx.selected } }));
    },
    /** Roles the current user holds in the current tenant. */
    available() {
      const ctx = Session.ctx;
      if (!ctx || !Array.isArray(ctx.roles)) return [];
      const tid = TenantCtx.id;
      return ctx.roles.filter((r) => (tid === null ? r.scope === 'global' : r.tenant_id === tid || r.scope === 'global'));
    },
    /** role name → permission codes cache (from GET /roles when permitted). */
    async rolePermissionMap() {
      if (RoleCtx._map && Date.now() - RoleCtx._mapAt < 60000) return RoleCtx._map;
      try {
        const { data } = await Api.get('/roles');
        const map = {};
        (data || []).forEach((r) => { map[r.name] = r.permissions || []; });
        RoleCtx._map = map;
        RoleCtx._mapAt = Date.now();
        return map;
      } catch {
        return null; // caller falls back to effective permissions
      }
    },
  };

  /* ------------------------------ PermissionGuard ------------------------------ */
  /**
   * Permission check for the UI.
   * Effective codes for the current tenant (+ platform global perms),
   * optionally narrowed to a single role selected in the role switcher.
   * NOTE: server-side enforcement is always authoritative (backend checks
   * the union of all active role grants).
   */
  function can(code, tenantId) {
    const ctx = Session.ctx;
    if (!ctx || !code) return false;
    const tid = tenantId !== undefined && tenantId !== null ? tenantId : TenantCtx.id;
    const perms = ctx.permissions || {};
    const codes = new Set();

    if (ctx.is_platform_admin && (perms.global || []).length) {
      perms.global.forEach((c) => codes.add(c));
    }
    const scoped = perms[String(tid)] || [];
    scoped.forEach((c) => codes.add(c));
    // Global (tenant-less) role grants apply everywhere for non-platform users too.
    (perms.global || []).forEach((c) => codes.add(c));

    // Narrow to a single selected role when the catalogue is available (UI only).
    const selectedRole = RoleCtx.selected;
    if (selectedRole !== 'effective') {
      const map = RoleCtx._map;
      if (map && Array.isArray(map[selectedRole])) {
        const rolePerms = new Set(map[selectedRole]);
        const narrowed = new Set([...codes].filter((c) => rolePerms.has(c)));
        return narrowed.has(code);
      }
    }
    return codes.has(code);
  }

  /** Current effective permission codes (for the perm pill). */
  function effectiveCodes() {
    const ctx = Session.ctx;
    if (!ctx) return [];
    const tid = TenantCtx.id;
    const perms = ctx.permissions || {};
    const set = new Set();
    if (ctx.is_platform_admin) (perms.global || []).forEach((c) => set.add(c));
    (perms[String(tid)] || []).forEach((c) => set.add(c));
    (perms.global || []).forEach((c) => set.add(c));
    const selectedRole = RoleCtx.selected;
    if (selectedRole !== 'effective' && RoleCtx._map && Array.isArray(RoleCtx._map[selectedRole])) {
      const rolePerms = new Set(RoleCtx._map[selectedRole]);
      return [...set].filter((c) => rolePerms.has(c)).sort();
    }
    return [...set].sort();
  }

  /** Permission chips UI helper: returns badge HTML or '' when denied. */
  function guard(code, html, tenantId) {
    return can(code, tenantId) ? html : '';
  }

  /* ------------------------------ TimerWidget ------------------------------ */
  const TimerWidget = {
    _intervals: new Set(),

    /**
     * Render a NIS2 timer pair (Art.21 24h + Art.23 72h) for an incident.
     * `incident` must include deadlines + timer_state from /incidents/timers.
     */
    html(incident) {
      const now = Date.now();
      const earlyDeadline = parseISO(incident.early_warning_deadline);
      const notifDeadline = parseISO(incident.notification_deadline);
      const status = incident.status;
      const done = status === 'notified_authority' || status === 'resolved' || status === 'closed';
      const earlyDone = !!incident.early_warning_sent_at || done;
      const notifDone = !!incident.notification_sent_at || status === 'notified_authority' || status === 'resolved' || status === 'closed';

      const earlyRemaining = earlyDeadline ? Math.max(0, (earlyDeadline.getTime() - now) / 1000) : 0;
      const notifRemaining = notifDeadline ? Math.max(0, (notifDeadline.getTime() - now) / 1000) : 0;

      const earlyOverdue = !earlyDone && earlyDeadline && now > earlyDeadline.getTime();
      const notifOverdue = !notifDone && notifDeadline && now > notifDeadline.getTime();

      const earlyPct = earlyDeadline && earlyDone ? 100
        : earlyDeadline ? Math.max(0, Math.min(100, (1 - earlyRemaining / (24 * 3600)) * 100)) : 0;
      const notifPct = notifDeadline && notifDone ? 100
        : notifDeadline ? Math.max(0, Math.min(100, (1 - notifRemaining / (72 * 3600)) * 100)) : 0;

      const earlyLabel = earlyDone
        ? (incident.early_warning_sent_at ? `SENT ${fmtRelative(incident.early_warning_sent_at)}` : 'SATISFIED')
        : (earlyOverdue ? 'OVERDUE — SEND NOW' : 'REMAINING');
      const notifLabel = notifDone
        ? (incident.notification_sent_at ? `SENT ${fmtRelative(incident.notification_sent_at)}` : 'SATISFIED')
        : (notifOverdue ? 'OVERDUE — NOTIFY NOW' : 'REMAINING');

      return `
        <div class="timer-row" data-timer-pair="${h(incident.id)}">
          <div class="timer-widget tw-article21 ${earlyDone ? 'tw-done' : ''} ${earlyOverdue ? 'tw-overdue' : ''}">
            <div class="tw-label"><span>NIS2 Art. 21 · Early warning ≤24h</span><span>${h(earlyLabel)}</span></div>
            <div class="tw-clock" data-clock="early" data-deadline="${h(incident.early_warning_deadline)}" data-done="${earlyDone ? '1' : '0'}">
              ${earlyDone ? (earlyOverdue ? 'LATE' : '✔ DONE') : fmtCountdown(earlyRemaining)}
            </div>
            <div class="tw-deadline">deadline ${h(incident.early_warning_deadline)}</div>
            <div class="tw-progress" style="width:${earlyPct.toFixed(1)}%; color: var(--cyan)"></div>
          </div>
          <div class="timer-widget tw-article23 ${notifDone ? 'tw-done' : ''} ${notifOverdue ? 'tw-overdue' : ''}">
            <div class="tw-label"><span>NIS2 Art. 23 · Authority ≤72h</span><span>${h(notifLabel)}</span></div>
            <div class="tw-clock" data-clock="notif" data-deadline="${h(incident.notification_deadline)}" data-done="${notifDone ? '1' : '0'}">
              ${notifDone ? (notifOverdue ? 'LATE' : '✔ DONE') : fmtCountdown(notifRemaining)}
            </div>
            <div class="tw-deadline">deadline ${h(incident.notification_deadline)}</div>
            <div class="tw-progress" style="width:${notifPct.toFixed(1)}%; color: var(--violet)"></div>
          </div>
        </div>`;
    },

    /**
     * Start a 1s ticker inside `root`:
     *  - [data-clock][data-deadline]  → NIS2 HH:MM:SS countdowns
     *  - [data-until]                 → JIT grant expiry countdowns
     * Updates immediately, then every second. Returns stop().
     */
    tick(root) {
      const update = () => {
        qsa('[data-clock]', root).forEach((el) => {
          if (el.dataset.done === '1') return;
          const dl = parseISO(el.dataset.deadline);
          if (!dl) return;
          const remaining = (dl.getTime() - Date.now()) / 1000;
          if (remaining <= 0) {
            el.textContent = '00:00:00';
            el.classList.add('expired');
            const widget = el.closest('.timer-widget');
            if (widget) widget.classList.add('tw-overdue');
          } else {
            el.textContent = fmtCountdown(remaining);
          }
        });
        qsa('[data-until]', root).forEach((el) => {
          const until = parseISO(el.dataset.until);
          if (!until) return;
          const inactive = el.dataset.active === '0';
          const remaining = (until.getTime() - Date.now()) / 1000;
          if (inactive || remaining <= 0) {
            el.textContent = 'EXPIRED';
            el.classList.add('expired');
          } else {
            el.textContent = fmtCountdown(remaining);
            el.classList.remove('expired');
          }
        });
      };
      update();
      const interval = setInterval(update, 1000);
      TimerWidget._intervals.add(interval);
      return () => {
        clearInterval(interval);
        TimerWidget._intervals.delete(interval);
      };
    },

    stopAll() {
      TimerWidget._intervals.forEach((i) => clearInterval(i));
      TimerWidget._intervals.clear();
    },
  };

  /* ------------------------------ HashChainBadge ------------------------------ */
  const HashChainBadge = {
    set(state, text) {
      const badge = qs('#chain-badge');
      const label = qs('#chain-badge-text');
      if (!badge || !label) return;
      badge.classList.remove('chain-valid', 'chain-invalid', 'chain-idle');
      if (state === 'valid') badge.classList.add('chain-valid');
      else if (state === 'invalid') badge.classList.add('chain-invalid');
      else badge.classList.add('chain-idle');
      label.textContent = text || (state === 'valid' ? 'chain valid' : state === 'invalid' ? 'CHAIN BROKEN' : 'chain unknown');
    },
    /** Query /audit/verify (needs audit:read) and update the sidebar badge. */
    async refresh() {
      if (!can('audit:read')) { HashChainBadge.set('idle', 'chain n/a'); return; }
      try {
        const { data } = await Api.get('/audit/verify');
        if (data && data.valid) HashChainBadge.set('valid', `chain valid · ${data.checked_count} links`);
        else HashChainBadge.set('invalid', `TAMPER @ #${data && data.first_mismatch ? data.first_mismatch.sequence_no : '?'}`);
      } catch {
        HashChainBadge.set('idle', 'chain unknown');
      }
    },
  };

  /* ------------------------------ Router ------------------------------ */
  const routes = {};       // name -> { path, render, perms? }
  let currentStop = null;  // cleanup fn of current page
  let currentName = null;

  function registerRoute(name, path, render) {
    routes[name] = { path, render };
  }

  function matchRoute(pathname) {
    const clean = (pathname || '/').replace(/\/+$/, '') || '/';
    if (clean === '/') return { name: 'dashboard' };
    for (const [name, r] of Object.entries(routes)) {
      if (r.path === clean) return { name };
    }
    return null;
  }

  function navigate(path, opts = {}) {
    if (opts.replace) history.replaceState({}, '', path);
    else history.pushState({}, '', path);
    renderCurrent();
  }

  function setActiveNav(name) {
    qsa('.nav-item').forEach((el) => {
      el.classList.toggle('active', el.dataset.route === name);
    });
  }

  async function renderCurrent() {
    const app = qs('#app');
    if (!app) return;

    // Stop page tickers/intervals.
    if (typeof currentStop === 'function') { try { currentStop(); } catch { /* noop */ } }
    currentStop = null;
    TimerWidget.stopAll();

    if (!Session.token) {
      // Call showLogin() directly — navigate() would re-enter renderCurrent()
      // and recurse forever while no token is present.
      showLogin();
      return;
    }

    const match = matchRoute(location.pathname);
    if (!match || match.name === 'login') {
      // Unknown path → dashboard; /login with token → dashboard.
      if (location.pathname.startsWith('/login')) { navigate('/', { replace: true }); return; }
      navigate('/', { replace: true });
      return;
    }

    currentName = match.name;
    setActiveNav(match.name);
    app.innerHTML = '<div class="page-loading"><div class="spinner"></div><p>Loading module…</p></div>';

    try {
      const stop = await routes[match.name].render(app);
      currentStop = typeof stop === 'function' ? stop : null;
      app.scrollTop = 0;
      window.scrollTo({ top: 0 });
    } catch (err) {
      console.error(err);
      app.innerHTML = `
        <div class="error-banner">
          <span><strong>Module failed:</strong> ${h(err.message || err)}</span>
          <button class="btn btn-sm btn-danger" onclick="location.reload()">Retry</button>
        </div>`;
    }
  }

  /* ------------------------------ Header chrome ------------------------------ */
  function renderTenantSwitcher() {
    const select = qs('#tenant-switcher');
    if (!select) return;
    const tenants = TenantCtx.list();
    const ctx = Session.ctx;
    const current = TenantCtx.id;
    let html = '';
    if (ctx && ctx.is_platform_admin) {
      html += `<option value="all"${current === null ? ' selected' : ''}>⚙ All tenants (platform)</option>`;
    }
    tenants.forEach((t) => {
      html += `<option value="${t.id}"${current === t.id ? ' selected' : ''}>${h(t.name)} · ${h(t.sector)}</option>`;
    });
    if (!tenants.length && !(ctx && ctx.is_platform_admin)) {
      html = '<option value="all">No tenants</option>';
    }
    select.innerHTML = html;
  }

  async function renderRoleSwitcher() {
    const select = qs('#role-switcher');
    if (!select) return;
    const roles = RoleCtx.available();
    if (RoleCtx.selected !== 'effective' && !roles.some((r) => r.name === RoleCtx.selected)) {
      RoleCtx.set('effective'); // stale selection after a tenant switch
    }
    const selected = RoleCtx.selected;
    let html = '<option value="effective">◈ Effective (all grants)</option>';
    roles.forEach((r) => {
      html += `<option value="${h(r.name)}"${selected === r.name ? ' selected' : ''}>${h(r.name)}${r.scope === 'global' ? ' ·global' : ''}</option>`;
    });
    select.innerHTML = html;

    // Try to load role → permissions catalogue (needs role:manage or user:manage).
    if (roles.length && selected !== 'effective') {
      const map = await RoleCtx.rolePermissionMap();
      if (map && !map[selected]) {
        // Selected role no longer exists → fall back.
        RoleCtx.set('effective');
        return renderRoleSwitcher();
      }
    }
    renderPermPill();
  }

  function renderPermPill() {
    const pill = qs('#perm-pill');
    if (!pill) return;
    const codes = effectiveCodes();
    const roleNote = RoleCtx.selected !== 'effective' ? ` [${RoleCtx.selected}]` : '';
    pill.textContent = codes.length ? `${codes.length} perms${roleNote}: ${codes.join(', ')}` : 'no permissions in context';
    pill.title = 'Effective UI permissions for the current tenant/role context (server enforces independently).';
  }

  function renderUserChip() {
    const ctx = Session.ctx;
    if (!ctx) return;
    const user = ctx.user || ctx;
    const nameEl = qs('#user-name');
    const roleEl = qs('#user-role');
    const avatar = qs('#user-avatar');
    if (nameEl) nameEl.textContent = user.full_name || user.email || '—';
    if (avatar) avatar.textContent = (user.full_name || user.email || '?').trim().charAt(0).toUpperCase();
    const roles = (ctx.roles || []).map((r) => r.name);
    if (roleEl) {
      roleEl.textContent = ctx.is_platform_admin
        ? 'platform_admin'
        : (roles.length ? roles.join(' · ') : 'no role');
    }
  }

  async function refreshChrome() {
    TenantCtx.ensureValid();
    renderTenantSwitcher();
    renderUserChip();
    await renderRoleSwitcher();
    HashChainBadge.refresh();
  }

  /* ------------------------------ boot ------------------------------ */
  async function boot() {
    // Wire global nav.
    document.addEventListener('click', (e) => {
      const link = e.target.closest('a[data-link]');
      if (link) {
        e.preventDefault();
        const href = link.getAttribute('href');
        if (href && href.startsWith('/')) navigate(href);
        qs('#sidenav') && qs('#sidenav').classList.remove('open');
        return;
      }
      if (e.target.matches('[data-modal-close]') || e.target.classList.contains('modal-close')) {
        Modal.close();
      }
    });
    window.addEventListener('popstate', () => { renderCurrent(); });

    const navToggle = qs('#nav-toggle');
    if (navToggle) navToggle.addEventListener('click', () => qs('#sidenav').classList.toggle('open'));

    const tenantSwitch = qs('#tenant-switcher');
    if (tenantSwitch) {
      tenantSwitch.addEventListener('change', () => {
        TenantCtx.set(tenantSwitch.value === 'all' ? null : parseInt(tenantSwitch.value, 10));
        RoleCtx.set('effective');
        renderCurrent().then(refreshChrome);
      });
    }
    const roleSwitch = qs('#role-switcher');
    if (roleSwitch) {
      roleSwitch.addEventListener('change', async () => {
        RoleCtx.set(roleSwitch.value);
        if (roleSwitch.value !== 'effective') await RoleCtx.rolePermissionMap();
        renderPermPill();
        renderCurrent();
      });
    }

    const logoutBtn = qs('#logout-btn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', async () => {
        try { await Api.post('/auth/logout', {}); } catch { /* token may already be dead */ }
        Session.clear();
        toast('Signed out.', 'success', 'Logout');
        navigate('/login', { replace: true });
      });
    }

    // Health pill on login screen.
    const health = qs('#health-pill');
    if (health) {
      Api.get('/health').then(({ data }) => {
        health.textContent = `API ${data.status} · sqlite ${data.database_version || ''}`;
        health.className = 'pill ' + (data.status === 'ok' ? 'pill-ok' : 'pill-warn');
      }).catch(() => {
        health.textContent = 'API unreachable';
        health.className = 'pill pill-err';
      });
    }

    // Route resolution.
    if (!Session.token) {
      showLogin();
      return;
    }
    try {
      await Session.refresh();
    } catch {
      showLogin();
      return;
    }
    showApp();
  }

  function showLogin() {
    qs('#login-view').classList.remove('hidden');
    qs('#app-view').classList.add('hidden');
    if (!location.pathname.startsWith('/login')) history.replaceState({}, '', '/login');
    if (window.BeeAuth && window.BeeAuth.initLogin) window.BeeAuth.initLogin();
  }

  async function showApp() {
    qs('#login-view').classList.add('hidden');
    qs('#app-view').classList.remove('hidden');
    if (location.pathname.startsWith('/login')) history.replaceState({}, '', '/');
    await refreshChrome();
    renderCurrent();
  }

  /* ------------------------------ exports ------------------------------ */
  window.App = {
    Api, Session, TenantCtx, RoleCtx, Modal,
    can, effectiveCodes, guard,
    TimerWidget, HashChainBadge,
    registerRoute, navigate, renderCurrent, refreshChrome,
    boot, showLogin, showApp,
    // shared utils
    h, qs, qsa, toast,
    fmtCountdown, fmtDateTime, fmtRelative, parseISO, toLocalInput, fromLocalInput,
  };
})();
