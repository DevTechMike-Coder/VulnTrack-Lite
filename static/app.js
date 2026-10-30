(() => {
  'use strict';

  const state = { items: [], filter: 'All', query: '', selected: null };
  const $ = (id) => document.getElementById(id);

  // ---------- DOM helpers (no innerHTML anywhere: all data goes through textContent) ----------
  function h(tag, cls, text, children) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text !== undefined && text !== null) el.textContent = text;
    (children || []).forEach((c) => el.appendChild(c));
    return el;
  }
  const icons = () => window.lucide && window.lucide.createIcons();

  // ---------- API ----------
  const TOKEN_KEY = 'vulntrack-token';
  async function api(method, path, body, extra) {
    const headers = { 'X-Requested-With': 'VulnTrack', ...(extra || {}) };
    const token = sessionStorage.getItem(TOKEN_KEY);
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    if (res.status === 401) {
      const entered = window.prompt('This VulnTrack instance requires an access token:');
      if (entered) {
        sessionStorage.setItem(TOKEN_KEY, entered);
        return api(method, path, body, extra);
      }
      throw new Error('Authentication required');
    }
    let data = null;
    try { data = await res.json(); } catch (_) { /* empty body */ }
    if (!res.ok) {
      const d = data && data.detail;
      const msg = Array.isArray(d) ? d.map((e) => e.msg.replace(/^Value error, /, '')).join('; ') : d;
      throw new Error(msg || `Request failed (${res.status})`);
    }
    return data;
  }

  // ---------- Toasts ----------
  function toast(message, type) {
    const colors = { success: 'border-emerald-500/30', error: 'border-rose-500/30', info: 'border-slate-700' };
    const el = h('div', `p-4 border rounded-xl shadow-2xl pointer-events-auto bg-slate-900 text-xs font-semibold text-slate-100 max-w-sm animate-fade-in ${colors[type] || colors.info}`, message);
    $('toast-container').appendChild(el);
    setTimeout(() => el.remove(), type === 'error' ? 7000 : 4000);
  }

  // ---------- Styling maps ----------
  const PRIORITY_STYLE = {
    0: 'bg-rose-500/15 text-rose-300 border border-rose-500/40',
    1: 'bg-amber-500/15 text-amber-300 border border-amber-500/40',
    2: 'bg-yellow-500/10 text-yellow-300 border border-yellow-500/30',
    3: 'bg-slate-500/10 text-slate-300 border border-slate-500/30',
  };
  const SEVERITY_STYLE = {
    Critical: 'bg-rose-500/10 text-rose-400 border border-rose-500/20',
    High: 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
    Medium: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
    Low: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
    None: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',
  };
  const scoreClass = (s) => (s >= 9 ? 'text-rose-500' : s >= 7 ? 'text-amber-500' : s >= 4 ? 'text-yellow-500' : 'text-emerald-500');
  const pct = (x) => (x === null || x === undefined ? '—' : `${(x * 100).toFixed(x < 0.1 ? 2 : 1)}%`);
  const BADGE = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-wide ';

  function priorityBadge(v) {
    return h('span', BADGE + PRIORITY_STYLE[v.priority], `P${v.priority} ${v.priority_label}`);
  }

  // ---------- Render ----------
  function visible() {
    const q = state.query.trim().toLowerCase();
    return state.items.filter((v) => {
      if (state.filter !== 'All' && String(v.priority) !== state.filter) return false;
      if (!q) return true;
      return v.cve_id.toLowerCase().includes(q) || v.title.toLowerCase().includes(q) || v.description.toLowerCase().includes(q);
    });
  }

  function renderMetrics() {
    const it = state.items;
    $('metric-total').textContent = it.length;
    $('metric-kev').textContent = it.filter((v) => v.kev).length;
    $('metric-crit-high').textContent = it.filter((v) => v.severity === 'Critical' || v.severity === 'High').length;
    $('metric-epss').textContent = it.filter((v) => v.epss !== null && v.epss >= 0.2).length;
    const stamps = it.map((v) => v.enriched_at).filter(Boolean).sort();
    $('intel-status').textContent = stamps.length ? `Intel refreshed ${new Date(stamps[stamps.length - 1]).toLocaleString()}` : 'Intel not refreshed yet';
  }

  function renderFilters() {
    document.querySelectorAll('#filter-group [data-filter]').forEach((b) => {
      const on = b.dataset.filter === state.filter;
      b.className = on
        ? 'px-4 py-1.5 rounded-lg text-xs font-semibold cursor-pointer bg-indigo-600 text-white shadow-sm'
        : 'px-4 py-1.5 rounded-lg text-xs font-medium cursor-pointer text-slate-400 hover:text-white';
      b.setAttribute('aria-pressed', String(on));
    });
  }

  function renderTable() {
    const body = $('vulnerabilities-list');
    const rows = visible();
    $('table-showing-text').textContent = `Showing ${rows.length} of ${state.items.length} vulnerabilities`;
    body.replaceChildren();
    if (!rows.length) {
      body.appendChild(h('tr', '', null, [h('td', 'py-12 text-center text-slate-400 text-sm', 'No vulnerabilities found. Add one or import a CVE from NVD.')]));
      body.firstChild.firstChild.colSpan = 7;
      return;
    }
    rows.forEach((v) => {
      const cveCell = h('td', 'py-3.5 px-4 font-mono text-sm text-indigo-400 font-semibold', v.cve_id);
      if (v.kev) cveCell.appendChild(h('span', 'ml-2 px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white', 'KEV'));
      const inspect = h('button', 'inline-flex items-center space-x-1 px-3 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white rounded-lg text-xs font-medium cursor-pointer', null, [
        h('span', '', 'Inspect'),
      ]);
      inspect.type = 'button';
      inspect.dataset.action = 'inspect';
      inspect.dataset.cve = v.cve_id;
      const title = h('td', 'py-3.5 px-4 text-sm text-white font-medium max-w-xs truncate', v.title);
      title.title = v.title;
      body.appendChild(h('tr', 'hover:bg-slate-900/30', null, [
        h('td', 'py-3.5 px-4', null, [priorityBadge(v)]),
        cveCell,
        title,
        h('td', 'py-3.5 px-4', null, [h('span', BADGE + (SEVERITY_STYLE[v.severity] || SEVERITY_STYLE.None), v.severity)]),
        h('td', 'py-3.5 px-4', null, [h('span', `font-bold text-sm ${scoreClass(v.score)}`, v.score.toFixed(1))]),
        h('td', 'py-3.5 px-4 text-sm text-slate-300', pct(v.epss)),
        h('td', 'py-3.5 px-4 text-right', null, [inspect]),
      ]));
    });
    icons();
  }

  function render() { renderMetrics(); renderFilters(); renderTable(); }

  async function load() {
    try {
      state.items = await api('GET', '/api/vulnerabilities');
      render();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  // ---------- Detail modal ----------
  function openDetail(cve) {
    const v = state.items.find((x) => x.cve_id === cve);
    if (!v) return;
    state.selected = v.cve_id;
    $('detail-cve').textContent = v.cve_id;
    $('detail-title').textContent = v.title;
    $('detail-desc').textContent = v.description;
    $('detail-badges').replaceChildren(
      priorityBadge(v),
      h('span', BADGE + (SEVERITY_STYLE[v.severity] || SEVERITY_STYLE.None), v.severity),
      h('span', `text-2xl font-extrabold ${scoreClass(v.score)}`, v.score.toFixed(1)),
    );
    const facts = [
      ['CVSS vector', v.cvss_vector || 'not recorded'],
      ['CVSS version', v.cvss_version || '—'],
      ['EPSS (30-day)', v.epss === null ? 'not fetched' : `${pct(v.epss)} (percentile ${pct(v.epss_percentile)})`],
      ['EPSS date', v.epss_date || '—'],
      ['CISA KEV', v.kev ? `added ${v.kev_date_added || '?'}, due ${v.kev_due_date || '?'}` : 'not listed'],
      ['Ransomware use', v.kev ? v.kev_ransomware || 'Unknown' : '—'],
      ['Published', v.published || '—'],
      ['Source', v.source],
    ];
    $('detail-facts').replaceChildren(...facts.map(([k, val]) => h('div', '', null, [h('dt', 'text-slate-500', k), h('dd', 'text-slate-200 font-mono break-all', val)])));
    $('detail-reasons').replaceChildren(...v.priority_reasons.map((r) => h('li', '', r)));
    $('detail-modal').classList.remove('hidden');
    icons();
  }
  const closeDetail = () => { $('detail-modal').classList.add('hidden'); state.selected = null; };

  // ---------- Add / import ----------
  const openAdd = () => { $('add-modal').classList.remove('hidden'); $('import-cve').focus(); };
  function closeAdd() {
    $('add-modal').classList.add('hidden');
    $('add-form').reset();
    $('import-form').reset();
  }

  async function submitAdd(ev) {
    ev.preventDefault();
    const payload = {
      cve_id: $('form-cve').value.trim(),
      title: $('form-title').value.trim(),
      description: $('form-desc').value.trim(),
    };
    const vector = $('form-vector').value.trim();
    const score = $('form-score').value.trim();
    if (vector) payload.cvss_vector = vector;
    if (score !== '') payload.score = parseFloat(score);
    try {
      const v = await api('POST', '/api/vulnerabilities', payload);
      toast(`Created ${v.cve_id} (${v.severity}, ${v.score.toFixed(1)})`, 'success');
      closeAdd();
      load();
    } catch (e) { toast(e.message, 'error'); }
  }

  async function submitImport(ev) {
    ev.preventDefault();
    const cve_id = $('import-cve').value.trim().toUpperCase();
    toast(`Importing ${cve_id}...`, 'info');
    try {
      const v = await api('POST', '/api/vulnerabilities/import', { cve_id });
      toast(`Imported ${v.cve_id}: P${v.priority} ${v.priority_label}`, 'success');
      closeAdd();
      load();
    } catch (e) { toast(e.message, 'error'); }
  }

  // ---------- Actions ----------
  async function enrich() {
    toast('Refreshing KEV and EPSS...', 'info');
    try {
      const r = await api('POST', '/api/enrich');
      r.warnings.forEach((w) => toast(w, 'error'));
      toast(`Updated ${r.updated} record(s), ${r.kev_hits} in KEV`, r.warnings.length ? 'info' : 'success');
      load();
    } catch (e) { toast(e.message, 'error'); }
  }

  async function deleteOne() {
    const id = state.selected;
    if (!id || !window.confirm(`Delete ${id}?`)) return;
    try {
      await api('DELETE', `/api/vulnerabilities/${encodeURIComponent(id)}`);
      closeDetail();
      toast(`Deleted ${id}`, 'success');
      load();
    } catch (e) { toast(e.message, 'error'); }
  }

  async function clearAll() {
    if (!window.confirm('Delete ALL vulnerabilities? This cannot be undone.')) return;
    try {
      await api('DELETE', '/api/vulnerabilities', undefined, { 'X-Confirm-Clear': 'delete-all' });
      toast('Database cleared', 'success');
      load();
    } catch (e) { toast(e.message, 'error'); }
  }

  const ACTIONS = {
    'open-add': openAdd,
    'close-add': closeAdd,
    'close-detail': closeDetail,
    enrich,
    clear: clearAll,
    'delete-one': deleteOne,
    inspect: (el) => openDetail(el.dataset.cve),
  };

  document.addEventListener('DOMContentLoaded', () => {
    document.addEventListener('click', (ev) => {
      const el = ev.target.closest('[data-action]');
      if (el && ACTIONS[el.dataset.action]) { ev.preventDefault(); ACTIONS[el.dataset.action](el); return; }
      const f = ev.target.closest('[data-filter]');
      if (f) { state.filter = f.dataset.filter; render(); }
    });
    document.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape') { closeAdd(); closeDetail(); }
    });
    $('search-input').addEventListener('input', (ev) => { state.query = ev.target.value; renderTable(); });
    $('add-form').addEventListener('submit', submitAdd);
    $('import-form').addEventListener('submit', submitImport);
    icons();
    load();
  });
})();
