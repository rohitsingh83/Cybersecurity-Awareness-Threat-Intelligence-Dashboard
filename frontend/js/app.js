/* Signal Atlas front end — vanilla JS, same-origin API only, no remote libraries or indicator requests. */
(() => {
  'use strict';
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const root = $('#view-root');
  const STATIC_MODE = document.documentElement.dataset.staticMode === 'true';
  window.SignalAtlasStaticMode = STATIC_MODE;
  const state = {
    view: 'overview', stats: null, trends: [], filters: { page: 1, page_size: 20, sort: 'newest' },
    iocQuery: 'login-check.invalid', lastIOC: null, openModule: null, quizResult: null,
    selectedTechnique: null, apiKey: localStorage.getItem('signal-atlas-api-key') || '',
    awarenessModules: [], lastQuiz: null,
  };
  const viewTitles = {
    overview: 'COMMAND CENTER', threats: 'THREAT STREAM', ioc: 'INDICATOR LOOKUP',
    vulnerabilities: 'VULNERABILITY LAB', alerts: 'ALERT QUEUE', attack: 'ATT&CK LENS',
    awareness: 'AWARENESS STUDIO', quiz: 'KNOWLEDGE CHECK', executive: 'EXECUTIVE BRIEF', guide: 'SYSTEM & API',
  };
  const demoNotice = '<div class="synthetic-banner"><span class="banner-mark">✳</span><span><strong>SYNTHETIC / DEMO ONLY</strong> &nbsp; Reserved example indicators · local dataset · no external lookups or connections</span></div>';

  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  }
  function num(value) { return Number(value || 0).toLocaleString(); }
  function date(value, short = false) {
    if (!value) return '—';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return esc(value);
    return new Intl.DateTimeFormat(undefined, short ? { month: 'short', day: '2-digit' } : { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(d);
  }
  function severityClass(value) { return `sev-${String(value || 'informational').toLowerCase().replace(/[^a-z]/g, '')}`; }
  function statusClass(value) { return `status-${String(value || 'new').toLowerCase().replace(/[^a-z_]/g, '')}`; }
  function severityBadge(value) { return `<span class="severity-badge ${severityClass(value)}">${esc(value || 'UNKNOWN')}</span>`; }
  function statusBadge(value) { return `<span class="status-badge ${statusClass(value)}">${esc(String(value || 'NEW').replaceAll('_', ' '))}</span>`; }
  function toast(message, type = 'ok', title = type === 'error' ? 'Could not complete' : 'Local action complete') {
    const region = $('#toast-region');
    const el = document.createElement('div');
    el.className = `toast ${type === 'error' ? 'error' : ''}`;
    el.innerHTML = `<strong>${esc(title)}</strong>${esc(message)}`;
    region.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateY(8px)'; setTimeout(() => el.remove(), 250); }, 3400);
  }
  async function api(path, options = {}) {
    if (STATIC_MODE) {
      if (typeof window.SignalAtlasStaticApi !== 'function') throw new Error('Static data adapter did not load. Refresh the GitHub Pages deployment.');
      return window.SignalAtlasStaticApi(path, options);
    }
    const headers = { ...(options.headers || {}) };
    if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    if (state.apiKey) headers['X-API-Key'] = state.apiKey;
    let response;
    try {
      response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
    } catch (error) {
      throw new Error('The local API is unavailable. Start the FastAPI server and retry.');
    }
    let payload;
    try { payload = await response.json(); } catch { payload = {}; }
    if (!response.ok) {
      const detail = payload.detail || `Request failed (${response.status})`;
      if (response.status === 401) toast('Add the configured analyst API key in System & API.', 'error', 'Authorization required');
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }
    return payload;
  }
  function setView(view) {
    if (!viewTitles[view]) view = 'overview';
    state.view = view;
    $$('.nav-item[data-view]').forEach((button) => button.classList.toggle('active', button.dataset.view === view));
    $('#view-kicker').textContent = viewTitles[view];
    history.replaceState(null, '', `#${view}`);
    renderView();
  }
  async function renderView() {
    root.innerHTML = '<div class="loading-line"></div><div class="empty-state" style="margin-top:18px"><strong>Opening local signal layer…</strong><span>Reading the synthetic database. No indicator is being contacted.</span></div>';
    root.classList.remove('view-enter');
    try {
      const renderers = {
        overview: renderOverview, threats: renderThreats, ioc: renderIOC,
        vulnerabilities: renderVulnerabilities, alerts: renderAlerts, attack: renderAttack,
        awareness: renderAwareness, quiz: renderQuiz, executive: renderExecutive, guide: renderGuide,
      };
      await renderers[state.view]();
      root.classList.add('view-enter');
      drawAmbientCharts();
    } catch (error) {
      root.innerHTML = `<div class="empty-state"><strong>Dashboard could not load</strong><span>${esc(error.message)}<br><br>${STATIC_MODE ? 'Confirm the GitHub Pages assets and bundled data files were published, then reload to retry.' : 'Confirm the backend is running and that the local SQLite database initialized successfully.'}</span><br><br><button class="button secondary" data-action="refresh-view">Retry</button></div>`;
    }
  }
  function pageHead(eyebrow, title, subtitle, actions = '') {
    return `<div class="page-head"><div><div class="eyebrow">${eyebrow}</div><h1 class="page-title">${title}</h1><p class="page-subtitle">${subtitle}</p></div><div class="head-actions">${actions}</div></div>`;
  }
  function kpi(label, value, foot, icon, accent = '', unit = '') {
    return `<div class="kpi-card ${accent}" style="--delay:${Math.random() * .16}s"><div class="kpi-top"><span>${label}</span><span class="kpi-icon">${icon}</span></div><div class="kpi-value" data-count="${Number(value || 0)}">${num(value)}${unit}</div><div class="kpi-foot">${foot}</div></div>`;
  }
  function chartPanel(title, caption, key, legend = '') {
    return `<section class="panel chart-panel"><div class="panel-header"><div><h2 class="panel-title">${title}</h2><div class="panel-caption">${caption}</div></div><span class="label-chip">LOCAL</span></div><div class="panel-body"><div class="chart-wrap"><canvas data-chart="${key}" aria-label="${title}" role="img"></canvas></div>${legend ? `<div class="chart-legend">${legend}</div>` : ''}</div></section>`;
  }
  function threatTable(items, compact = false) {
    if (!items?.length) return '<div class="empty-state"><strong>No records match this view</strong><span>Try clearing a filter. A match is an observation for review, not a confirmed incident.</span></div>';
    return `<div class="table-panel"><div class="table-scroll"><table><thead><tr><th>Record</th><th>Threat / category</th><th>Indicator</th><th>Severity</th><th>Risk</th><th>Confidence</th><th>Last seen</th><th>Status</th></tr></thead><tbody>${items.map((t) => `<tr data-threat-id="${esc(t.threat_id)}" tabindex="0" aria-label="Open ${esc(t.threat_id)}"><td class="threat-id">${esc(t.threat_id)}</td><td><div class="threat-name-cell">${esc(t.threat_name)}</div><div class="category-text">${esc(t.threat_category)}</div></td><td class="indicator-cell" title="${esc(t.indicator_value)}">${esc(t.indicator_value)}</td><td>${severityBadge(t.severity)}</td><td class="score-cell">${num(t.risk_score)}<span style="color:#6b7890">/100</span></td><td class="confidence-cell">${num(t.confidence_score)}%</td><td>${date(t.last_seen, true)}</td><td>${statusBadge(t.status)}</td></tr>`).join('')}</tbody></table></div>${compact ? '' : `<div class="table-footer"><span>${num(items.length)} records in this page · all values are synthetic</span><span class="table-actions"><span>Sort and filters apply to local records</span></span></div>`}</div>`;
  }
  function barList(entries, colors = ['var(--cyan)'], limit = 8) {
    const rows = Object.entries(entries || {}).sort((a, b) => Number(b[1]) - Number(a[1])).slice(0, limit);
    if (!rows.length) return '<div class="chart-empty">No mapped items</div>';
    const max = Math.max(1, ...rows.map((x) => Number(x[1])));
    return `<div class="bar-list">${rows.map(([label, value], i) => `<div class="bar-row"><span title="${esc(label)}">${esc(label.replaceAll('_', ' '))}</span><span class="bar-track"><i class="bar-fill" style="width:${Math.max(3, Number(value) / max * 100)}%;--bar:${colors[i % colors.length]};background:linear-gradient(90deg,var(--cyan2),${colors[i % colors.length]})"></i></span><strong>${num(value)}</strong></div>`).join('')}</div>`;
  }

  async function renderOverview() {
    const [stats, trendData, recent, alertData] = await Promise.all([
      api('/api/dashboard/stats'), api('/api/dashboard/trends?days=21'), api('/api/threats?page=1&page_size=8&sort=risk'), api('/api/alerts?limit=5'),
    ]);
    state.stats = stats; state.trends = trendData.items || [];
    $('#nav-threat-count').textContent = num(stats.total_threat_records);
    $('#nav-alert-count').textContent = num(alertData.total_returned);
    root.innerHTML = `
      <section class="hero-panel"><div class="hero-orbit"></div><div class="hero-content"><div class="eyebrow"><span class="pulse-dot"></span> THREAT SIGNAL / LEARNING LOOP</div><h1>See the signal.<br><em>Teach the human.</em></h1><p>A local-first intelligence observatory for synthetic threat data, evidence-aware triage, vulnerability context, and security habits. One cockpit, two defense layers.</p><div class="hero-tags"><span class="label-chip cyan">◉ OFFLINE DATA</span><span class="label-chip">IOC ≠ INCIDENT</span><span class="label-chip">RISK ≠ CONFIDENCE</span><span class="label-chip amber">2,000+ SYNTHETIC OBSERVATIONS</span></div></div><div class="hero-aside"><strong>HYD / 17°23′ N</strong>LOCAL SIGNAL FIELD<br><span class="coordinate">SYNTHETIC SECTOR · 2026</span></div></section>
      ${demoNotice}
      <div class="kpi-grid">
        ${kpi('Threat records', stats.total_threat_records, 'Local synthetic observations', '⌁')}
        ${kpi('Critical review', stats.critical_threats, 'High potential priority · not confirmed', '⬢', 'kpi-critical')}
        ${kpi('High review', stats.high_threats, 'Evidence-aware analyst queue', '↑', 'kpi-high')}
        ${kpi('Active indicators', stats.active_indicators, 'Not closed / not false-positive', '◉', 'kpi-blue')}
        ${kpi('Open investigations', stats.open_investigations, 'Generated alerts awaiting triage', '⚑', 'kpi-violet')}
        ${kpi('Avg confidence', stats.average_confidence, 'Evidence quality · separate from risk', '◎', 'kpi-lime', '%')}
        ${kpi('Vulnerability lab', stats.vulnerabilities_tracked, 'Fictional prioritization scenarios', '◈', 'kpi-high')}
      </div>
      <div class="grid-2">
        ${chartPanel('Threat activity', 'Synthetic observations by first event date · trailing sample', 'trend', '<span><i class="legend-dot" style="--dot:var(--cyan)"></i>OBSERVATIONS</span><span><i class="legend-dot" style="--dot:var(--violet)"></i>AVG RISK</span>')}
        <section class="panel chart-panel"><div class="panel-header"><div><h2 class="panel-title">Severity constellation</h2><div class="panel-caption">Risk classification bands · analyst review only</div></div><span class="label-chip amber">RISK</span></div><div class="panel-body"><div class="donut-row"><canvas class="donut-canvas" data-chart="severity" aria-label="Threats by severity" role="img"></canvas><div class="legend-list" id="severity-legend"></div></div></div></section>
      </div>
      <div class="grid-2">
        <section class="panel chart-panel"><div class="panel-header"><div><h2 class="panel-title">Category pressure</h2><div class="panel-caption">Where the fictional signal mix is concentrated</div></div><span class="label-chip">10 CATEGORIES</span></div><div class="panel-body" id="category-bars">${barList(stats.threats_by_category)}</div></section>
        <section class="panel chart-panel"><div class="panel-header"><div><h2 class="panel-title">Indicator anatomy</h2><div class="panel-caption">Indicator type distribution · syntax says nothing about reputation</div></div><span class="label-chip cyan">IOC MIX</span></div><div class="panel-body"><div class="donut-row"><canvas class="donut-canvas" data-chart="indicators" aria-label="Indicator type distribution" role="img"></canvas><div class="legend-list" id="indicator-legend"></div></div></div></section>
      </div>
      <div class="grid-2">
        <section class="panel"><div class="panel-header"><div><h2 class="panel-title">ATT&CK behavior map</h2><div class="panel-caption">Only mappings supported by synthetic behavior descriptions</div></div><button class="text-link" data-view="attack">Open lens ↗</button></div><div class="panel-body">${barList(Object.fromEntries(stats.top_attack_tactics.map((x) => [x.tactic, x.count])), ['var(--violet)','var(--cyan)','var(--amber)'], 5)}<div class="attack-caution">ATT&CK describes behavior context. An IP, domain, or hash alone does not establish a technique or actor.</div></div></section>
        <section class="panel"><div class="panel-header"><div><h2 class="panel-title">Risk / evidence spread</h2><div class="panel-caption">Independent distributions · don't combine into a verdict</div></div><span class="label-chip">0—100</span></div><div class="panel-body"><div class="metric-line"><span>Average risk</span><strong class="tone-amber">${num(stats.average_risk)} / 100</strong></div><div class="metric-line"><span>Average confidence</span><strong class="tone-cyan">${num(stats.average_confidence)} / 100</strong></div><div class="metric-line"><span>Risk scored high or critical (61+)</span><strong>${num((stats.risk_distribution['61–80']||0)+(stats.risk_distribution['81–100']||0))}</strong></div><div class="metric-line"><span>Confidence with strong evidence (81+)</span><strong>${num(stats.confidence_distribution['81–100']||0)}</strong></div><div class="attention-card" style="margin-top:7px"><div class="attention-title">Analyst lens</div><p>A score prioritizes investigation; it does not state that an organization is compromised.</p></div></div></section>
      </div>
      <div class="grid-2">
        ${chartPanel('Risk score distribution', 'Potential concern bands · 0–100', 'risk')}
        ${chartPanel('Confidence distribution', 'Evidence-quality bands · independent from risk', 'confidence')}
      </div>
      <div class="grid-2">
        ${chartPanel('Vulnerabilities by severity', 'CVSS severity for fictional classroom scenarios', 'vulnerabilities')}
        ${chartPanel('Threat workflow status', 'Records by triage lifecycle state', 'statuses')}
      </div>
      <div class="section-heading"><div><h2>Priority records</h2><p>Highest synthetic risk first · click a row to open the investigation view</p></div><button class="text-link" data-view="threats">View threat stream →</button></div>
      ${threatTable(recent.items, true)}
      <div class="grid-2"><section class="panel"><div class="panel-header"><div><h2 class="panel-title">Signal queue</h2><div class="panel-caption">Alerts request review; none are a confirmed incident by default</div></div><button class="text-link" data-view="alerts">Open queue →</button></div><div>${alertData.items.slice(0,4).map(alertMini).join('') || '<div class="panel-body">No alert records</div>'}</div></section><section class="attention-card"><div class="attention-title">✦ Awareness follows the signal</div><p>When phishing or account-security patterns appear in the demo feed, use the matching awareness module as a learning nudge—not as an accusation or employee score.</p><button class="button small" style="margin-top:12px" data-view="awareness">Explore awareness studio <span>↗</span></button></section></div>`;
    fillLegend('#severity-legend', stats.threats_by_severity, ['#ff6f78','#ffc76b','#a98aff','#74a7ff','#74829a']);
    fillLegend('#indicator-legend', stats.indicator_type_distribution, ['#5df0e3','#a98aff','#ffc76b','#74a7ff','#ff7eaa','#b7f56b']);
    countUp();
  }
  function alertMini(alert) {
    const action = alert.alert_type === 'HIGH_PRIORITY_VULNERABILITY'
      ? '<button class="text-link" data-view="vulnerabilities" aria-label="Open vulnerability lab">↗</button>'
      : `<button class="text-link" data-threat-id="${esc(alert.threat_id)}" aria-label="Open alert threat">↗</button>`;
    return `<div class="alert-row"><div class="alert-symbol">⚑</div><div><div class="alert-title">${esc(alert.alert_type.replaceAll('_',' '))} · ${esc(alert.indicator_value)}</div><div class="alert-meta">${esc(alert.threat_id || 'Fictional vulnerability scenario')} · ${num(alert.risk_score)} risk / ${num(alert.confidence_score)}% confidence</div></div>${severityBadge(alert.severity)}${action}</div>`;
  }
  function fillLegend(selector, entries, colors) {
    const el = $(selector); if (!el) return;
    const items = Object.entries(entries || {}).sort((a,b) => b[1]-a[1]);
    const total = items.reduce((sum, item) => sum + Number(item[1]), 0);
    el.innerHTML = items.slice(0, 6).map(([label, value], index) => `<div class="legend-row"><i class="legend-dot" style="--dot:${colors[index % colors.length]}"></i><span>${esc(label.replaceAll('_',' '))}</span><strong>${num(value)}</strong></div>`).join('') + `<div class="legend-row" style="padding-top:4px;border-top:1px solid rgba(255,255,255,.05)"><span>Total</span><strong>${num(total)}</strong></div>`;
  }

  async function renderThreats() {
    const params = new URLSearchParams({ page: state.filters.page, page_size: state.filters.page_size, sort: state.filters.sort });
    for (const key of ['severity','category','indicator_type','status','min_risk','min_confidence','q','from_date','to_date']) {
      if (state.filters[key] !== undefined && state.filters[key] !== '' && state.filters[key] !== 'ALL') params.set(key, state.filters[key]);
    }
    const result = await api(`/api/threats?${params.toString()}`);
    root.innerHTML = `${pageHead('TECHNICAL INTELLIGENCE / STREAM', 'Threat stream', 'Normalize, filter, and triage synthetic observations. Use context, risk, and confidence separately.', '<button class="button secondary" data-action="export-csv">⇩ Export current dataset</button><button class="button" data-view="ioc">⌕ Search IOC</button>')}${demoNotice}
      <div class="mini-stat-row" style="margin-bottom:14px"><div class="mini-stat"><small>Records matching</small><strong>${num(result.total)}</strong></div><div class="mini-stat"><small>Page</small><strong>${result.page} / ${result.pages}</strong></div><div class="mini-stat"><small>Current sort</small><strong>${esc(state.filters.sort)}</strong></div><div class="mini-stat"><small>Signal meaning</small><strong class="tone-cyan">Review, not verdict</strong></div></div>
      <div class="filter-bar"><input class="filter-select filter-search" id="threat-q" value="${esc(state.filters.q || '')}" placeholder="Search ID, category, indicator, description…"><select class="filter-select" id="filter-severity"><option value="ALL">All severities</option>${['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'].map((x)=>`<option ${state.filters.severity===x?'selected':''}>${x}</option>`).join('')}</select><select class="filter-select" id="filter-category"><option value="ALL">All categories</option>${['PHISHING','MALWARE','RANSOMWARE','CREDENTIAL THREATS','WEB THREATS','NETWORK THREATS','VULNERABILITY EXPOSURE','SOCIAL ENGINEERING','DATA EXPOSURE','ACCOUNT SECURITY'].map((x)=>`<option ${state.filters.category===x?'selected':''}>${x}</option>`).join('')}</select><select class="filter-select" id="filter-type"><option value="ALL">All indicator types</option>${['IP ADDRESS','DOMAIN','URL','FILE HASH','EMAIL/SENDER DOMAIN','CVE ID'].map((x)=>`<option ${state.filters.indicator_type===x?'selected':''}>${x}</option>`).join('')}</select><select class="filter-select" id="filter-status"><option value="ALL">All statuses</option>${['NEW','UNDER_REVIEW','MONITORING','CLOSED','FALSE_POSITIVE'].map((x)=>`<option ${state.filters.status===x?'selected':''}>${x}</option>`).join('')}</select><select class="filter-select" id="filter-sort">${[['newest','Newest'],['risk','Highest risk'],['confidence','Highest confidence'],['observed','Most observed'],['oldest','Oldest']].map(([v,l])=>`<option value="${v}" ${state.filters.sort===v?'selected':''}>${l}</option>`).join('')}</select></div>
      <div class="filter-bar"><label class="range-filter">Minimum risk <input type="range" id="filter-risk" min="0" max="100" value="${Number(state.filters.min_risk || 0)}"><span class="filter-value" id="risk-filter-value">${Number(state.filters.min_risk || 0)}</span></label><label class="range-filter">Minimum confidence <input type="range" id="filter-confidence" min="0" max="100" value="${Number(state.filters.min_confidence || 0)}"><span class="filter-value" id="confidence-filter-value">${Number(state.filters.min_confidence || 0)}</span></label><label class="range-filter">From <input class="filter-select filter-date" type="date" id="filter-date-from" value="${esc(state.filters.from_date||'')}"></label><label class="range-filter">To <input class="filter-select filter-date" type="date" id="filter-date-to" value="${esc(state.filters.to_date||'')}"></label><button class="button ghost small" data-action="clear-filters">Reset filters</button></div>
      ${threatTable(result.items)}
      <div class="table-footer"><span>Page ${result.page} of ${result.pages} · ${num(result.total)} matching records</span><span class="table-actions"><button class="button secondary small" data-action="page-prev" ${result.page<=1?'disabled':''}>← Previous</button><button class="button secondary small" data-action="page-next" ${result.page>=result.pages?'disabled':''}>Next →</button></span></div>`;
  }
  function applyThreatFilters() {
    const q = $('#threat-q'); if (q) state.filters.q = q.value.trim();
    for (const [id,key] of [['filter-severity','severity'],['filter-category','category'],['filter-type','indicator_type'],['filter-status','status'],['filter-sort','sort']]) {
      const el = $('#'+id); if (el) state.filters[key] = el.value === 'ALL' ? '' : el.value;
    }
    const r = $('#filter-risk'), c = $('#filter-confidence');
    if (r) state.filters.min_risk = Number(r.value); if (c) state.filters.min_confidence = Number(c.value);
    const dateFrom = $('#filter-date-from'), dateTo = $('#filter-date-to');
    if (dateFrom) state.filters.from_date = dateFrom.value; if (dateTo) state.filters.to_date = dateTo.value;
    state.filters.page = 1; renderThreats();
  }

  async function renderIOC() {
    const result = state.lastIOC;
    root.innerHTML = `${pageHead('LOCAL LOOKUP / ZERO OUTBOUND', 'IOC lookup', 'Check only the bundled synthetic dataset. This tool never resolves DNS, visits a URL, contacts an IP, or opens a file.', '<span class="label-chip cyan">▣ LOCAL DATABASE ONLY</span>')}${demoNotice}
      <section class="search-hero"><div class="eyebrow">INDICATOR / SEARCH BY EXACT VALUE</div><h2 style="font-size:20px;margin:8px 0 2px;letter-spacing:-.03em">Ask the local signal archive.</h2><p class="page-subtitle">Supported: IPv4/IPv6 · domain · URL · MD5/SHA-1/SHA-256 shape · CVE ID</p><form id="ioc-search-form" class="search-input-row"><input id="ioc-query" name="q" value="${esc(state.iocQuery)}" placeholder="198.51.100.25 or login-check.invalid" autocomplete="off"><button class="button" type="submit">⌕ Search locally</button></form><div class="search-disclaimer">Syntactic validation ≠ maliciousness. Indicator match ≠ confirmed compromise. Never paste secrets or personal information.</div></section>
      <div class="correlation-list" style="margin:12px 0"><button class="label-chip cyan" data-search-indicator="login-check.invalid">DEMO DOMAIN · login-check.invalid</button><button class="label-chip" data-search-indicator="198.51.100.25">RESERVED IP · 198.51.100.25</button><button class="label-chip" data-search-indicator="CVE-2099-10001">SYNTHETIC CVE · 2099</button></div>
      <div id="ioc-result-area">${result ? renderIOCResult(result) : '<div class="empty-state"><strong>Ready for local lookup</strong><span>Type or choose an example indicator above. The query uses local demo data only; no external lookups are made.</span></div>'}</div>`;
    if (!state.lastIOC && state.iocQuery) lookupIOC(state.iocQuery, false);
  }
  function renderIOCResult(data) {
    if (!data.valid) return `<div class="panel search-result"><div class="panel-body"><div class="empty-state"><strong>Syntax not recognized</strong><span>${esc(data.validation_notes)}</span></div></div></div>`;
    const known = !!data.known_in_demo_dataset;
    const cell = (label, value, cls = '') => `<div class="result-cell"><div class="result-label">${label}</div><div class="result-value ${cls}">${value}</div></div>`;
    return `<section class="panel search-result"><div class="panel-header"><div><h2 class="panel-title">${known ? 'Local intelligence context' : 'No exact local match'}</h2><div class="panel-caption">${esc(data.interpretation)}</div></div><span class="label-chip ${known?'cyan':''}">${known?'KNOWN IN DEMO':'NOT IN DEMO'}</span></div><div class="panel-body"><div class="result-grid">${cell('Indicator type',esc(data.indicator_type))}${cell('Known in demo dataset',known?'<span class="tone-cyan">YES</span>':'NO')}${cell('Risk score',data.risk_score===null?'—':`${num(data.risk_score)} / 100`, 'tone-amber')}${cell('Confidence',data.confidence_score===null?'—':`${num(data.confidence_score)}%`, 'tone-cyan')}${cell('Severity',data.severity?severityBadge(data.severity):'—')}${cell('Category',esc((data.categories||[]).join(', ')||'—'))}${cell('First seen',date(data.first_seen))}${cell('Last seen',date(data.last_seen))}${cell('Status',data.status?statusBadge(data.status):'—')}${cell('Source reliability',esc(data.source_reliability||'—'))}</div><div class="rule-line"></div><div class="detail-grid"><div class="detail-field"><small>Normalized value</small><span class="indicator-code">${esc(data.normalized_value)}</span></div><div class="detail-field"><small>Source names</small><span>${esc((data.source_names||[]).join(', ')||'No local source match')}</span></div></div>${data.related_indicators?.length?`<div class="drawer-section"><h3>Related indicators · shared synthetic campaign ID</h3><div class="correlation-list">${data.related_indicators.map((x)=>`<button class="correlation-chip" data-search-indicator="${esc(x)}">${esc(x)} ↗</button>`).join('')}</div></div>`:''}${data.internal_sightings?.length?`<div class="drawer-section"><h3>Local signal correlation</h3><div class="metric-line"><span>Matching synthetic internal signals</span><strong>${data.internal_sightings.length}</strong></div><p class="panel-caption">${data.internal_sightings.map((s)=>esc(s.event_type)).join(' · ')} · sample telemetry only</p></div>`:''}${data.mitre_mappings?.length?`<div class="drawer-section"><h3>Behavior context · ATT&CK</h3>${data.mitre_mappings.map((m)=>`<div class="technique-chip" data-technique="${esc(m.technique_id||'')}"><span class="technique-id">${esc(m.technique_id||'—')}</span><span class="technique-name">${esc(m.tactic||'')} / ${esc(m.technique||'')}</span></div>`).join('')}</div>`:''}${data.matches?.length?`<div class="drawer-section"><h3>Associated records</h3>${data.matches.map((m)=>`<div class="metric-line"><button class="text-link" data-threat-id="${esc(m.threat_id)}">${esc(m.threat_id)} · ${esc(m.threat_name)} ↗</button>${severityBadge(m.severity)}</div>`).join('')}</div>`:''}${data.related_alerts?.length?`<div class="drawer-section"><h3>Related alerts</h3>${data.related_alerts.slice(0,4).map((a)=>`<div class="metric-line"><span>${esc(a.alert_type.replaceAll('_',' '))}</span>${statusBadge(a.status)}</div>`).join('')}</div>`:''}<div class="attention-card" style="margin-top:15px"><div class="attention-title">Interpret carefully</div><p>An IOC can be stale, shared by benign infrastructure, or incomplete. A match is one piece of evidence—not a confirmed attack.</p></div></div></section>`;
  }
  async function lookupIOC(value, showToast = true) {
    const q = String(value || '').trim(); if (!q) return;
    state.iocQuery = q;
    const area = $('#ioc-result-area'); if (area) area.innerHTML = '<div class="loading-line"></div>';
    try {
      const data = await api(`/api/indicators/search?q=${encodeURIComponent(q)}`);
      state.lastIOC = data;
      const target = $('#ioc-result-area'); if (target) target.innerHTML = renderIOCResult(data);
      if (showToast) toast(data.known_in_demo_dataset ? 'Exact local synthetic match found.' : 'No exact match in the local synthetic dataset.');
    } catch (error) { if (area) area.innerHTML = `<div class="empty-state"><strong>Lookup unavailable</strong><span>${esc(error.message)}</span></div>`; }
  }

  async function renderVulnerabilities() {
    const severity = state.vulnSeverity || '';
    const data = await api(`/api/vulnerabilities?${severity?`severity=${encodeURIComponent(severity)}`:''}`);
    const items = data.items || [];
    root.innerHTML = `${pageHead('PATCH CONTEXT / FICTIONAL SCENARIOS', 'Vulnerability lab', 'Prioritize with context, not CVSS alone. Compare asset criticality, exposure, demo exploitation evidence, and business context.', '<span class="label-chip amber">24 SYNTHETIC SCENARIOS</span>')}${demoNotice}<div class="vuln-notice"><strong>Data note:</strong> The CVE-shaped IDs use the fictional year 2099 for classroom practice. They are not real advisories and do not describe exploitable software.</div>
      <div class="filter-bar"><select class="filter-select" id="vuln-severity"><option value="">All CVSS severities</option>${['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'].map((x)=>`<option value="${x}" ${severity===x?'selected':''}>${x}</option>`).join('')}</select><label class="range-filter">Minimum priority <input type="range" id="vuln-priority" min="0" max="100" value="${state.minPriority||0}"><span class="filter-value" id="priority-filter-value">${state.minPriority||0}</span></label><span class="label-chip">Sorted by contextual priority</span></div>
      <div class="grid-3">${items.filter((v)=>Number(v.priority_score)>=(state.minPriority||0)).map((v)=>`<article class="vulnerability-card"><div class="vuln-top"><span class="vuln-id">${esc(v.cve_id)} <span style="color:#596780">· DEMO</span></span>${severityBadge(v.severity)}</div><div class="vuln-product">${esc(v.product_category)}</div><div class="vuln-desc">${esc(v.description)}<br><br><span style="color:#b8a7e8">${esc(v.priority_explanation)}</span></div><div class="vuln-metrics"><div><small>CVSS</small><strong>${Number(v.cvss_score).toFixed(1)} / 10</strong></div><div><small>Priority</small><strong class="tone-amber">${num(v.priority_score)} / 100</strong></div><div><small>Patch</small><strong>${v.patch_available?'Available':'Not marked'}</strong></div><div><small>Asset criticality</small><strong>${v.asset_criticality}/100</strong></div><div><small>Exposure</small><strong>${v.exposure_score}/100</strong></div><div><small>Demo exploitation</small><strong>${v.exploitation_status_demo==='YES'?'<span class="tone-amber">Flagged</span>':'No'}</strong></div></div><div class="priority-track"><i style="width:${v.priority_score}%"></i></div><div class="module-foot"><span>Published ${esc(v.published_date)}</span><span class="label-chip">SYNTHETIC</span></div></article>`).join('')}</div>
      <div class="grid-2"><section class="attention-card"><div class="attention-title">CVSS is a starting signal, not a patch plan.</div><p>A lower-CVSS scenario on an exposed, business-critical service can outrank a higher-CVSS item isolated in a disposable lab. Validate asset ownership and patch guidance in an authorized environment.</p></section><section class="panel"><div class="panel-header"><div><h2 class="panel-title">Prioritization recipe</h2><div class="panel-caption">Illustrative weighting inside the local scoring engine</div></div></div><div class="panel-body"><div class="metric-line"><span>CVSS base score</span><strong>30%</strong></div><div class="metric-line"><span>Asset criticality</span><strong>25%</strong></div><div class="metric-line"><span>Exposure</span><strong>15%</strong></div><div class="metric-line"><span>Known exploitation evidence</span><strong>20%</strong></div><div class="metric-line"><span>Business context</span><strong>10%</strong></div></div></section></div>`;
  }

  async function renderAlerts() {
    const status = state.alertFilter || '';
    const data = await api(`/api/alerts?limit=250${status?`&status=${encodeURIComponent(status)}`:''}`);
    const items = data.items || [];
    root.innerHTML = `${pageHead('SOC TRIAGE / HUMAN-IN-THE-LOOP', 'Alert queue', 'Deduplicated signals for analyst review. Update workflow status, open the linked threat, and document decisions.', '<span class="label-chip amber">ALERT ≠ INCIDENT</span>')}${demoNotice}<div class="mini-stat-row" style="margin-bottom:14px"><div class="mini-stat"><small>Returned</small><strong>${num(items.length)}</strong></div><div class="mini-stat"><small>New / investigating</small><strong>${num(items.filter((x)=>['NEW','INVESTIGATING'].includes(x.status)).length)}</strong></div><div class="mini-stat"><small>Highest risk</small><strong class="tone-amber">${num(Math.max(0,...items.map((x)=>x.risk_score)))}</strong></div></div><div class="filter-bar"><select class="filter-select" id="alert-filter"><option value="">All alert statuses</option>${['NEW','INVESTIGATING','MONITORING','RESOLVED','FALSE_POSITIVE'].map((x)=>`<option ${status===x?'selected':''}>${x}</option>`).join('')}</select><span class="label-chip">${items.length ? 'Repeated signals grouped locally' : 'No current alerts'}</span></div><section class="panel">${items.length?items.map((a)=>`<div class="alert-row"><div class="alert-symbol">⚑</div><div><div class="alert-title">${esc(a.alert_type.replaceAll('_',' '))} · ${esc(a.indicator_value)}</div><div class="alert-meta">${esc(a.alert_id)} · ${esc(a.threat_id||'No linked threat')} · ${date(a.timestamp)} · ${num(a.observation_count)} observation(s)</div><div class="alert-meta">Risk ${num(a.risk_score)} / confidence ${num(a.confidence_score)}% · ${esc(a.description)}</div></div>${severityBadge(a.severity)}<div class="alert-actions"><select class="select-mini alert-status-select" data-alert-id="${esc(a.alert_id)}">${['NEW','INVESTIGATING','MONITORING','RESOLVED','FALSE_POSITIVE'].map((x)=>`<option ${a.status===x?'selected':''}>${x}</option>`).join('')}</select>${a.alert_type==='HIGH_PRIORITY_VULNERABILITY'?'<button class="button secondary small" data-view="vulnerabilities">Review CVE ↗</button>':`<button class="button secondary small" data-threat-id="${esc(a.threat_id||'')}">Investigate ↗</button>`}</div></div>`).join(''):'<div class="empty-state" style="margin:14px"><strong>No alerts in this view</strong><span>Alerts are generated as review signals from synthetic risk thresholds, repetitions, or explicit relationships.</span></div>'}</section><div class="attention-card" style="margin-top:13px"><div class="attention-title">Alert fatigue control</div><p>Repeated observations of the same indicator in a short window should be grouped into one review item with a count. Correlation reduces noise; it does not prove attribution.</p></div>`;
  }

  async function renderAttack() {
    const [data, stats] = await Promise.all([api('/api/attack/tactics'), api('/api/dashboard/stats')]);
    const tactics = data.tactics || [], techniques = data.techniques || [];
    let selectedRecords = null;
    if (state.selectedTechnique) selectedRecords = await api(`/api/attack/techniques/${encodeURIComponent(state.selectedTechnique)}/threats`);
    root.innerHTML = `${pageHead('BEHAVIOR MAPPING / EVIDENCE REQUIRED', 'ATT&CK lens', 'Explore supported tactic and technique mappings for fictional records. Click a technique to see the linked synthetic observations.', '<span class="label-chip cyan">NO IOC-ONLY MAPPING</span>')}${demoNotice}<div class="attack-caution">An IOC says <strong>what artifact</strong> was observed. ATT&CK can describe <strong>how behavior</strong> relates to adversary techniques. Mapping is not attribution and is omitted when behavioral context is insufficient.</div>
      <div class="attack-hero" style="margin-top:13px"><section class="panel"><div class="panel-header"><div><h2 class="panel-title">Tactics represented</h2><div class="panel-caption">ATT&CK tactic labels from behavior-backed synthetic mapping</div></div></div><div class="panel-body">${tactics.length?tactics.map((item)=>`<div class="tactic-card" style="margin-bottom:8px"><h3>${esc(item.tactic)}</h3><p>${num(item.count)} synthetic records · tactic describes an objective, not a specific artifact.</p></div>`).join(''):'<div class="empty-state"><strong>No justified mappings</strong><span>Insufficient behavior context is a valid result.</span></div>'}</div></section><section class="panel"><div class="panel-header"><div><h2 class="panel-title">Technique frequency</h2><div class="panel-caption">Select a mapped technique to inspect associated records</div></div></div><div class="panel-body">${techniques.length?techniques.map((t)=>`<button class="technique-chip" style="width:100%;text-align:left" data-technique="${esc(t.technique_id)}"><span class="technique-id">${esc(t.technique_id)}</span><span class="technique-name">${esc(t.technique)}</span><span class="technique-count">${num(t.count)} records ↗</span></button>`).join(''):'<div class="empty-state"><strong>No techniques</strong><span>Only map when justified.</span></div>'}</div></section></div>
      ${selectedRecords?`<div class="section-heading"><div><h2>Associated records · ${esc(state.selectedTechnique)}</h2><p>${num(selectedRecords.total)} records · attribution not established</p></div><button class="button ghost small" data-action="clear-technique">Clear selection</button></div>${threatTable(selectedRecords.items,true)}`:''}
      <div class="grid-3"><div class="guide-card"><h3>TACTIC / WHY</h3><p>The high-level objective a behavior is intended to accomplish, such as Initial Access or Credential Access.</p></div><div class="guide-card"><h3>TECHNIQUE / HOW</h3><p>A described way that an objective may be achieved. A technique needs behavior evidence, not just an IP or domain match.</p></div><div class="guide-card"><h3>SUB-TECHNIQUE / DETAIL</h3><p>A more specific variant under a technique. This demo avoids sub-technique assertions unless evidence supports them.</p></div></div>`;
  }

  async function renderAwareness() {
    const data = await api('/api/awareness/modules');
    state.awarenessModules = data.items || [];
    root.innerHTML = `${pageHead('HUMAN DEFENSE / MICRO-LEARNING', 'Awareness studio', 'Short, actionable lessons that build safer habits. Learning is private, supportive, and separate from threat-risk scoring.', '<button class="button" data-view="quiz">◉ Start knowledge check</button>')}${demoNotice}<div class="attention-card" style="margin-bottom:13px"><div class="attention-title">15 bite-sized modules · one small habit at a time</div><p>Choose a card to open its warning signs, safe practices, and response guidance. Modules are educational; a quiz score is not an employee fitness or competency judgment.</p></div><div class="awareness-grid">${state.awarenessModules.map((m)=>{
      const open = state.openModule === m.id;
      const warnings = (m.warning_signs||[]).slice(0,3).map((x)=>`<li>${esc(x)}</li>`).join('');
      const practices = (m.safe_practices||[]).slice(0,4).map((x)=>`<li>${esc(x)}</li>`).join('');
      return `<article class="module-card ${open?'expanded':''}" data-module-card="${esc(m.id)}"><div class="module-top"><span class="module-icon">${esc(m.icon||'✳')}</span><span class="module-category">${esc(m.category)}</span></div><h3>${esc(m.title)}</h3><p>${esc(m.what)}</p><div class="module-foot"><span>${open?'LESSON OPEN':'60-SECOND READ'}</span><span class="module-arrow">${open?'−':'↗'}</span></div>${open?`<div class="module-detail"><h4>Why it matters</h4><p>${esc(m.why)}</p><h4>Warning signs</h4><ul>${warnings}</ul><h4>Safer practices</h4><ul>${practices}</ul><h4>If something happens</h4><p>${esc(m.if_something_happens)}</p><div class="module-task"><strong>1-minute task:</strong> ${esc(m.quick_task)}</div></div>`:''}</article>`;
    }).join('')}</div>`;
  }

  async function renderQuiz() {
    const data = await api('/api/quiz');
    const questions = data.questions || [];
    const resultHtml = state.quizResult ? renderQuizResult(state.quizResult) : '';
    root.innerHTML = `${pageHead('LEARN / REFLECT / IMPROVE', 'Knowledge check', `${questions.length} scenario-based questions across ten defensive topics. Unanswered questions count as incorrect; retake at any time.`, '<button class="button secondary" data-view="awareness">↩ Awareness studio</button>')}${demoNotice}${resultHtml}<form id="quiz-form"><div class="quiz-shell"><div class="quiz-list">${questions.map((q, index)=>`<section class="quiz-question" data-question="${esc(q.id)}"><div class="quiz-qtop"><span class="quiz-number">QUESTION ${String(index+1).padStart(2,'0')} / ${String(questions.length).padStart(2,'0')}</span><span class="quiz-category">${esc(q.category)}</span></div><h3>${esc(q.question)}</h3><div class="quiz-options">${q.options.map((option, optionIndex)=>`<label class="quiz-option"><input type="radio" name="${esc(q.id)}" value="${optionIndex}"><span>${String.fromCharCode(65+optionIndex)}. ${esc(option)}</span></label>`).join('')}</div></section>`).join('')}</div><aside class="quiz-side"><div class="eyebrow" style="text-align:center">YOUR LEARNING RUN</div><div class="quiz-progress-ring" id="quiz-ring" style="--progress:0%"><strong id="quiz-progress">0/${questions.length}</strong></div><h3>Progress, not judgment.</h3><p>${STATIC_MODE ? 'Answers are stored as a score summary in this browser only.' : 'Answers are stored as a score summary in the local SQLite database.'} No name is required.</p><div class="metric-line"><span>Topics</span><strong>10</strong></div><div class="metric-line"><span>Questions</span><strong>${questions.length}</strong></div><button class="button" type="submit" style="width:100%;margin-top:14px">Score my learning run ↗</button><div class="exec-note">Educational self-reflection only — not an employee competency assessment.</div></aside></div></form>`;
    updateQuizProgress();
  }
  function renderQuizResult(result) {
    const cats = Object.entries(result.category_scores||{}).sort((a,b)=>a[1]-b[1]);
    const recommendations = (result.recommendations||[]).filter((x)=>x.score<80).slice(0,4);
    const answers = (result.results||[]).filter((x)=>!x.is_correct).slice(0,5);
    return `<section class="quiz-results"><div class="eyebrow">LEARNING RUN COMPLETE · ${num(result.correct_answers)}/${num(result.total_questions)} CORRECT</div><div style="display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap;margin-top:9px"><div><div class="result-score">${num(result.overall_score)}<small> / 100</small></div><div class="score-label">${esc(result.label)}</div></div><div class="attention-card" style="max-width:450px"><div class="attention-title">A learning signal, not a judgment</div><p>${esc(result.educational_notice||'Use this score to choose a refresher module, not to judge a person.')}</p></div></div><div class="score-bars">${cats.map(([key,value])=>`<div class="score-bar-card"><small>${esc(key.replaceAll('_',' '))}</small><strong>${num(value)}%</strong><div class="priority-track"><i style="width:${value}%;background:linear-gradient(90deg,var(--violet),var(--cyan))"></i></div></div>`).join('')}</div><div class="module-foot" style="margin-top:10px"><span>FOCUS AREAS: ${esc((result.weakest_areas||[]).join(' · ')||'None')}</span><span>Scores use quiz responses only</span></div>${recommendations.length?`<div class="drawer-section"><h3>Personalized refreshers</h3>${recommendations.map((r)=>`<div class="recommendation-row"><span>${esc(r.category)} · ${num(r.score)}%</span><button class="text-link" data-open-module="${esc(r.module_id)}">${esc(r.recommendation)} ↗</button></div>`).join('')}</div>`:'<div class="drawer-section"><h3>Learning recommendations</h3><p>No immediate refresher is suggested by the selected threshold. Keep practicing and revisit modules periodically.</p></div>'}${answers.length?`<div class="drawer-section"><h3>Review a few concepts</h3>${answers.map((r)=>`<div class="note-card"><strong>${esc(r.category)}</strong> · ${esc(r.explanation)}</div>`).join('')}</div>`:''}</section>`;
  }
  function updateQuizProgress() {
    const ring = $('#quiz-ring'); const label = $('#quiz-progress'); if (!ring || !label) return;
    const total = $$('input[type="radio"]', root).filter((x)=>x.checked).length;
    const questionCount = $$('.quiz-question', root).length;
    const pct = questionCount ? Math.round(total/questionCount*100) : 0;
    ring.style.setProperty('--progress', `${pct}%`); label.textContent = `${total}/${questionCount}`;
  }

  async function renderExecutive() {
    const data = await api('/api/executive/summary');
    const trends = data.awareness_score_trend || [];
    root.innerHTML = `${pageHead('LEADERSHIP VIEW / PLAIN LANGUAGE', 'Executive brief', 'A concise view of synthetic signal volume, remediation context, and awareness learning. Use as a demo narrative—not as a real organizational assessment.', '<span class="label-chip amber">DEMO MODEL ONLY</span>')}${demoNotice}<div class="executive-grid"><section class="executive-score"><div class="eyebrow">ILLUSTRATIVE ORG RISK INDEX</div><div class="exec-score-number">${num(data.illustrative_organizational_risk_score)}<small> / 100</small></div><p>${esc(data.plain_language_summary)}</p><div class="hero-tags"><span class="label-chip">ALERT PRESSURE · ${num(data.score_components.alert_pressure_40_percent)}</span><span class="label-chip">VULN CONTEXT · ${num(data.score_components.demo_vulnerability_context_40_percent)}</span><span class="label-chip">COMPLETION GAP · ${num(data.score_components.awareness_completion_gap_20_percent)}</span></div></section><section class="panel"><div class="panel-header"><div><h2 class="panel-title">Leadership priorities</h2><div class="panel-caption">Plain-language, non-destructive next steps</div></div></div><div class="panel-body"><div class="priority-list">${data.recommended_defensive_priorities.map((x,i)=>`<div class="priority-item"><span class="priority-index">0${i+1}</span><span>${esc(x)}</span></div>`).join('')}</div><div class="exec-note">Scores are illustrative and based only on fictional demo inputs. Do not use for operational decisions.</div></div></section></div><div class="grid-2"><section class="panel"><div class="panel-header"><div><h2 class="panel-title">Threat landscape summary</h2><div class="panel-caption">Top categories from the local synthetic archive</div></div></div><div class="panel-body">${(data.top_threat_categories||[]).map((x,i)=>`<div class="metric-line"><span><span class="tone-cyan">0${i+1}</span> &nbsp; ${esc(x.category.replaceAll('_',' '))}</span><strong>${num(x.records)} observations</strong></div>`).join('')}<div class="metric-line"><span>High + critical review records</span><strong class="tone-amber">${num(data.high_critical_threat_count)}</strong></div><div class="metric-line"><span>High/critical alerts open</span><strong>${num(data.high_critical_alert_count)}</strong></div><div class="metric-line"><span>Known-exploited demo CVEs matching assets</span><strong>${num(data.known_exploited_demo_cves_affecting_assets)}</strong></div><div class="metric-line"><span>Synthetic awareness completion rate</span><strong>${num(data.awareness_completion_rate_demo)}%</strong></div><div class="metric-line"><span>Alerts currently open</span><strong>${num(data.open_investigations)}</strong></div></div></section><section class="panel"><div class="panel-header"><div><h2 class="panel-title">Vulnerability focus areas</h2><div class="panel-caption">Contextual priority, not CVSS-only sorting</div></div><button class="text-link" data-view="vulnerabilities">Open lab →</button></div><div class="panel-body">${(data.top_vulnerability_categories||[]).map((x,i)=>`<div class="metric-line"><span>${esc(x)}</span><strong class="tone-amber">SCENARIO ${i+1}</strong></div>`).join('')}<div class="attention-card" style="margin-top:10px"><div class="attention-title">Validate exposure + ownership</div><p>Real patch priority depends on an authorized asset inventory, product/version context, compensating controls, and change windows.</p></div></div></section></div><div class="grid-2"><section class="panel"><div class="panel-header"><div><h2 class="panel-title">Awareness signal</h2><div class="panel-caption">Opt-in educational quiz outcomes saved locally without a name</div></div><button class="text-link" data-view="quiz">Take knowledge check →</button></div><div class="panel-body">${data.awareness_latest_score===null?'<div class="empty-state"><strong>No quiz results yet</strong><span>Complete the optional self-guided knowledge check to create a local learning trend.</span></div>':`<div class="result-score">${num(data.awareness_latest_score)}<small> / 100</small></div><div class="score-label">LATEST EDUCATIONAL SCORE</div>${trends.slice(0,6).map((x)=>`<div class="metric-line"><span>${date(x.created_at)}</span><strong>${num(x.overall_score)}%</strong></div>`).join('')}`}<div class="exec-note">This is not an employee fitness or competency judgment.</div></div></section><section class="attention-card"><div class="attention-title">Management narrative</div><p>Threat intelligence helps prioritize defensive investigation; awareness content helps people recognize and report risk. The two loops reinforce one another, but neither replaces technical controls, authorized investigation, or incident-response policy.</p><button class="button small" style="margin-top:12px" data-view="awareness">Review human-defense modules ↗</button></section></div>`;
  }

  async function renderGuide() {
    const data = await api('/api/system/guide');
    const endpoints = [
      ['GET','/api/threats','Filtered threat list; severity/category/type/status/risk/confidence/sort/page.'],['GET','/api/threats/{id}','Investigation detail, relationships, timeline, notes, mappings.'],['POST','/api/threats','Create normalized observation; analyst key required when configured.'],['PUT','/api/threats/{id}','Update review status; analyst key required when configured.'],['GET','/api/indicators/search?q=…','Syntax check + exact local-only indicator search.'],['GET','/api/dashboard/stats','KPIs and chart distributions.'],['GET','/api/dashboard/trends','Synthetic daily trend series.'],['GET','/api/alerts','Alert queue with status/severity filters.'],['PUT','/api/alerts/{id}/status','Update alert workflow status; analyst key required when configured.'],['POST','/api/threats/{id}/notes','Add analyst note; analyst key required when configured.'],['GET','/api/vulnerabilities','Synthetic CVSS/context prioritization scenarios.'],['GET','/api/awareness/modules','15 micro-learning modules.'],['GET','/api/quiz','30 questions without answer keys.'],['POST','/api/quiz/submit','Score, category results, recommendations.'],['GET','/api/executive/summary','Plain-language demo summary and illustrative risk index.'],['GET','/api/attack/tactics','Supported tactic/technique distribution.'],['GET','/api/docs','Interactive OpenAPI documentation.'],
    ];
    root.innerHTML = `${pageHead('SYSTEM TRANSPARENCY / BUILD NOTES', 'System & API', 'See how the dashboard classifies evidence, how to secure local write actions, and which routes power the interface.', (STATIC_MODE ? '<span class="label-chip cyan">GITHUB PAGES · BROWSER-ONLY</span>' : '<a class="button secondary" href="/api/docs" target="_blank" rel="noopener">Open API docs ↗</a>'))}${demoNotice}${STATIC_MODE ? '<div class="attention-card" style="margin-bottom:13px"><div class="attention-title">GitHub Pages mode · no server</div><p>The site runs entirely in your browser. Bundled CSV/JSON files provide the baseline; changes are saved locally in this browser and are not shared across devices.</p></div>' : ''}<div class="guide-grid"><section class="guide-card"><h3>Signal language</h3><p>A clear evidence ladder keeps the dashboard honest. These terms represent different confidence and response states, not synonyms.</p>${Object.entries(data.classification).map(([k,v])=>`<div class="metric-line"><strong>${esc(k.toUpperCase())}</strong><span>${esc(v)}</span></div>`).join('')}</section><section class="guide-card"><h3>Safety rails</h3><ul>${data.safety.map((x)=>`<li>${esc(x)}</li>`).join('')}</ul><p><strong>Demo boundary:</strong> use synthetic local data only. No suspicious URL, IP, or file is contacted, opened, or executed.</p></section>${STATIC_MODE ? `<section class="guide-card"><h3>Independent browser storage</h3><p>This GitHub Pages build has no backend server or API key. Threat records load from the bundled static dataset; notes, workflow changes, and quiz results are stored in this browser's localStorage only.</p><button class="button danger small" data-action="reset-browser-data">Reset this browser's demo changes</button></section>` : `<section class="guide-card"><h3>Analyst API key</h3><p>Local demo writes are open only when <code>TI_API_KEY</code> is unset. For a local protected demo, configure the same key in the backend environment and here. Never expose this demo publicly as-is.</p><div class="api-key-row"><input class="form-input" id="api-key-input" type="password" autocomplete="off" placeholder="Optional local X-API-Key" value="${esc(state.apiKey)}"><button class="button" data-action="save-api-key">Save locally</button></div><p id="api-key-status">${state.apiKey?'A key is stored in this browser profile.':'No browser key stored.'}</p></section>`}<section class="guide-card"><h3>Data relationships</h3><ul>${data.database_design.map((x)=>`<li>${esc(x)}</li>`).join('')}</ul><p>${STATIC_MODE ? 'The bundled files mirror the demo data model; the static build reads them directly in-browser.' : 'SQLite indexes are applied to threat category, severity, indicator, timestamp, status, alert workflow, and notes.'}</p></section></div>${STATIC_MODE ? `<section class="guide-card"><h3>Static client architecture</h3><p>This GitHub Pages deployment does not host REST API routes. The browser adapter reads the bundled CSV/JSON files and applies filters, scoring, enrichment, and quiz logic locally. Notes, status changes, and quiz results are stored only in this browser's localStorage.</p><p>For the FastAPI + SQLite REST API and OpenAPI docs, run the backend locally using the repository README.</p></section>` : `<div class="section-heading"><div><h2>REST API map</h2><p>All requests stay on this host; indicator lookup is a database operation</p></div><span class="label-chip cyan">FASTAPI · SQLITE</span></div><section class="guide-card">${endpoints.map(([method,path,desc])=>`<div class="api-row"><span class="api-method">${method}</span><span class="api-route">${esc(path)}</span><span class="api-desc">${esc(desc)}</span></div>`).join('')}</section>`}<div class="grid-2"><section class="guide-card"><h3>${STATIC_MODE ? 'Optional: full backend locally' : 'Run locally'}</h3><p><code>python -m venv .venv</code><br><code>source .venv/bin/activate</code> (Windows: <code>.venv\Scripts\activate</code>)<br><code>pip install -r requirements.txt</code><br><code>python data/generate_threat_data.py</code><br><code>uvicorn backend.app:app --reload --host 0.0.0.0</code></p>${STATIC_MODE ? '<p><strong>Preview static Pages build:</strong> <code>python -m http.server 8080 --directory docs</code></p>' : ''}</section><section class="guide-card"><h3>Production boundary</h3><p>This project is a student demo, not an enterprise deployment. Add identity, RBAC, HTTPS termination, secret management, audit logging, stronger rate limiting, backups, and environment-specific feed governance before any authorized production use.</p></section></div>`;
  }

  async function openThreat(id) {
    if (!id) return;
    try {
      const threat = await api(`/api/threats/${encodeURIComponent(id)}`);
      renderDetailDrawer(threat);
    } catch (error) { toast(error.message, 'error'); }
  }
  function renderDetailDrawer(t) {
    const overlay = $('#overlay'), panel = $('#detail-panel');
    const related = t.related_indicators || [], notes = t.analyst_notes || [], alerts = t.related_alerts || [], mappings = t.attack_mappings || [], timeline = t.timeline || [];
    panel.innerHTML = `<div class="drawer-head"><div><div class="drawer-id">${esc(t.threat_id)} · SYNTHETIC OBSERVATION</div><h2>${esc(t.threat_name)}</h2><div class="drawer-tags">${severityBadge(t.severity)}${statusBadge(t.status)}<span class="label-chip">${esc(t.threat_category)}</span></div></div><button class="drawer-close" data-close-drawer aria-label="Close investigation">✕</button></div><div class="drawer-score-grid"><div class="drawer-score"><small>Risk / priority</small><strong class="tone-amber">${num(t.risk_score)}<span style="font-size:10px;color:#77849a"> / 100</span></strong></div><div class="drawer-score"><small>Confidence / evidence</small><strong class="tone-cyan">${num(t.confidence_score)}<span style="font-size:10px;color:#77849a">%</span></strong></div></div><div class="attention-card"><div class="attention-title">OBSERVATION ≠ INCIDENT</div><p>Risk estimates potential concern. Confidence estimates evidence quality. Neither score confirms compromise; use authorized telemetry and analyst judgment.</p></div><div class="drawer-section"><h3>Record context</h3><div class="detail-grid"><div class="detail-field"><small>Indicator type</small><span>${esc(t.indicator_type)}</span></div><div class="detail-field"><small>Indicator value</small><span class="indicator-code">${esc(t.indicator_value)}</span></div><div class="detail-field"><small>Source</small><span>${esc(t.source_name)} · reliability ${esc(t.source_reliability)}</span></div><div class="detail-field"><small>First seen</small><span>${date(t.first_seen)}</span></div><div class="detail-field"><small>Last seen</small><span>${date(t.last_seen)}</span></div><div class="detail-field"><small>Observation count</small><span>${num(t.observed_count)}</span></div><div class="detail-field"><small>Region</small><span>${esc(t.country_or_region_optional||'Not provided')}</span></div><div class="detail-field"><small>Campaign key</small><span>${esc(t.campaign_id||'No explicit group')}</span></div></div></div><div class="drawer-section"><h3>Analyst description</h3><p>${esc(t.description)}</p></div><div class="drawer-section"><h3>Workflow status</h3><div class="detail-actions"><select class="form-select" id="threat-status-select" data-threat-status="${esc(t.threat_id)}">${['NEW','UNDER_REVIEW','MONITORING','CLOSED','FALSE_POSITIVE'].map((x)=>`<option ${t.status===x?'selected':''}>${x}</option>`).join('')}</select><button class="button secondary small" data-search-indicator="${esc(t.indicator_value)}">Enrich IOC locally</button></div></div><div class="drawer-section"><h3>Recommended defensive next steps</h3><div class="attention-card"><p>• Review related internal logs through authorized tools<br>• Check for authorized sightings in the relevant telemetry<br>• Review email-security telemetry if applicable<br>• Use the matching awareness module as a learning nudge<br>• Monitor or resolve with documented analyst rationale</p></div></div>${related.length?`<div class="drawer-section"><h3>Related indicators · shared demo campaign</h3>${related.map((r)=>`<div class="metric-line"><button class="text-link" data-search-indicator="${esc(r.indicator_value)}">${esc(r.indicator_type)} · ${esc(r.indicator_value)} ↗</button>${severityBadge(r.severity)}</div>`).join('')}<div class="exec-note">Correlation suggests a relationship only; attribution is not established.</div></div>`:''}<div class="drawer-section"><h3>ATT&CK mapping</h3>${mappings.length?mappings.map((m)=>`<div class="technique-chip" data-technique="${esc(m.technique_id_optional||'')}"><span class="technique-id">${esc(m.technique_id_optional||'—')}</span><span class="technique-name">${esc(m.tactic)} · ${esc(m.technique||'Tactic context only')}</span></div>`).join(''):'<p>No mapping: available evidence does not justify one. A raw indicator is not behavior.</p>'}</div>${t.cve_id_optional?`<div class="drawer-section"><h3>CVE association</h3><p>${esc(t.cve_id_optional)} · fictional synthetic CVE identifier</p></div>`:''}<div class="drawer-section"><h3>Investigation timeline</h3><div class="timeline">${timeline.map((x)=>`<div class="timeline-item"><strong>${esc(x.label)}</strong><small>${date(x.time)} · ${esc(x.detail)}</small></div>`).join('')}</div></div><div class="drawer-section"><h3>Related alerts (${alerts.length})</h3>${alerts.length?alerts.map((a)=>`<div class="metric-line"><span>${esc(a.alert_type.replaceAll('_',' '))} · ${esc(a.alert_id)}</span>${statusBadge(a.status)}</div>`).join(''):'<p>No alert linked to this record.</p>'}</div><div class="drawer-section"><h3>Analyst notes</h3><div id="notes-list">${notes.length?notes.map((n)=>`<div class="note-card">${esc(n.note)}<small>${esc(n.author_label||'LOCAL ANALYST')} · ${date(n.created_at)}</small></div>`).join(''):'<div class="note-card">No analyst notes recorded yet.</div>'}</div><form id="note-form" data-threat-id="${esc(t.threat_id)}"><textarea class="form-textarea" id="note-text" rows="3" maxlength="1000" placeholder="Document evidence, decision, or next step. Avoid unnecessary personal data."></textarea><button class="button small" type="submit" style="margin-top:7px">＋ Add analyst note</button></form></div><div class="exec-note">Synthetic dataset · no external connection · risk score is a triage aid only.</div>`;
    overlay.hidden = false; document.body.style.overflow = 'hidden';
  }
  function closeDrawer() { $('#overlay').hidden = true; document.body.style.overflow = ''; }

  async function exportCSV() {
    try {
      const params = new URLSearchParams({ page_size: '100', sort: state.filters.sort || 'newest' });
      for (const key of ['severity','category','indicator_type','status','min_risk','min_confidence','q','from_date','to_date']) if (state.filters[key]) params.set(key,state.filters[key]);
      const first = await api(`/api/threats?${params}&page=1`);
      const pages = Math.min(100, first.pages || 1); let all = [...first.items];
      for (let page = 2; page <= pages; page++) { const next = await api(`/api/threats?${params}&page=${page}`); all.push(...next.items); }
      const fields = ['threat_id','timestamp','threat_name','threat_category','indicator_type','indicator_value','source_name','source_reliability','confidence_score','severity','risk_score','status','first_seen','last_seen','mitre_tactic_optional','mitre_technique_optional','cve_id_optional','synthetic_label'];
      const csv = [fields.join(','), ...all.map((row)=>fields.map((key)=>`"${String(row[key]??'').replaceAll('"','""')}"`).join(','))].join('\r\n');
      const blob = new Blob([csv], {type:'text/csv;charset=utf-8'}); const url = URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download='signal-atlas-synthetic-threats.csv'; a.click(); URL.revokeObjectURL(url);
      toast(`Exported ${num(all.length)} local synthetic records.`);
    } catch(error) { toast(error.message,'error'); }
  }
  function countUp() {
    $$('[data-count]', root).forEach((el)=>{
      const target = Number(el.dataset.count); if (!Number.isFinite(target)) return;
      const start = performance.now(); const duration = 650;
      function tick(now) { const p=Math.min(1,(now-start)/duration); const eased=1-Math.pow(1-p,3); el.textContent=Math.round(target*eased).toLocaleString(); if(p<1) requestAnimationFrame(tick); }
      requestAnimationFrame(tick);
    });
  }
  function drawAmbientCharts() {
    if (!state.stats) return;
    const colors=['#5df0e3','#a98aff','#ffc76b','#74a7ff','#ff7eaa','#b7f56b','#f08da8','#74dfbc'];
    $$('canvas[data-chart]',root).forEach((canvas)=>{
      const key=canvas.dataset.chart;
      if(key==='severity') drawDonut(canvas,Object.entries(state.stats.threats_by_severity||{}),colors);
      else if(key==='indicators') drawDonut(canvas,Object.entries(state.stats.indicator_type_distribution||{}),colors);
      else if(key==='trend') drawTrend(canvas,state.trends||[]);
      else if(key==='risk') drawBars(canvas,Object.entries(state.stats.risk_distribution||{}),colors);
      else if(key==='confidence') drawBars(canvas,Object.entries(state.stats.confidence_distribution||{}),['#5df0e3','#74a7ff','#a98aff','#b7f56b','#ffc76b']);
      else if(key==='vulnerabilities') drawBars(canvas,Object.entries(state.stats.vulnerabilities_by_severity||{}),['#ff6f78','#ffc76b','#a98aff','#74a7ff','#74829a']);
      else if(key==='statuses') drawBars(canvas,Object.entries(state.stats.threat_status_distribution||{}),['#5df0e3','#ffc76b','#a98aff','#b7f56b','#ff7eaa']);
    });
  }
  function prepCanvas(canvas) {
    const rect = canvas.getBoundingClientRect(), ratio = Math.max(1, window.devicePixelRatio || 1);
    canvas.width = Math.floor(rect.width * ratio); canvas.height = Math.floor(rect.height * ratio);
    const ctx = canvas.getContext('2d'); ctx.setTransform(ratio,0,0,ratio,0,0);
    return {ctx,w:rect.width,h:rect.height};
  }
  function drawDonut(canvas, entries, colors) {
    if(!canvas || !entries.length) return;
    const {ctx,w,h}=prepCanvas(canvas), total=entries.reduce((s,x)=>s+Number(x[1]),0); if(!total) return;
    const size=Math.min(w,h)-8, r=size/2-4, cx=w/2, cy=h/2, thickness=Math.max(11,size*.13); let angle=-Math.PI/2;
    entries.forEach(([label,value],i)=>{
      const slice=Number(value)/total*Math.PI*2;
      ctx.beginPath();ctx.arc(cx,cy,r,angle+.018,angle+slice-.018);ctx.strokeStyle=colors[i%colors.length];ctx.lineWidth=thickness;ctx.lineCap='round';ctx.shadowColor=colors[i%colors.length];ctx.shadowBlur=7;ctx.stroke();ctx.shadowBlur=0;angle+=slice;
    });
    ctx.fillStyle='#eaf3fb';ctx.textAlign='center';ctx.textBaseline='middle';ctx.font='700 18px system-ui';ctx.fillText(total.toLocaleString(),cx,cy-3);ctx.fillStyle='#728199';ctx.font='700 7px system-ui';ctx.fillText('RECORDS',cx,cy+13);
  }
  function drawTrend(canvas, series) {
    if(!canvas || !series.length) return;
    const {ctx,w,h}=prepCanvas(canvas); const pad={l:12,r:8,t:10,b:23}, iw=w-pad.l-pad.r, ih=h-pad.t-pad.b;
    const vals=series.map(x=>Number(x.observations||0)), max=Math.max(1,...vals), min=Math.min(...vals,0);
    ctx.strokeStyle='rgba(151,174,214,.12)';ctx.lineWidth=1;
    for(let i=0;i<4;i++){const y=pad.t+ih*i/3;ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke();}
    const pts=vals.map((v,i)=>({x:pad.l+(series.length===1?iw/2:iw*i/(series.length-1)),y:pad.t+ih-(v-min)/(max-min||1)*ih}));
    const grad=ctx.createLinearGradient(0,pad.t,0,h-pad.b);grad.addColorStop(0,'rgba(93,240,227,.24)');grad.addColorStop(1,'rgba(93,240,227,0)');ctx.beginPath();pts.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.lineTo(pts.at(-1).x,h-pad.b);ctx.lineTo(pts[0].x,h-pad.b);ctx.closePath();ctx.fillStyle=grad;ctx.fill();
    ctx.beginPath();pts.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.strokeStyle='#5df0e3';ctx.lineWidth=2;ctx.shadowColor='rgba(93,240,227,.55)';ctx.shadowBlur=8;ctx.stroke();ctx.shadowBlur=0;
    pts.forEach((p,i)=>{if(i%Math.max(1,Math.floor(pts.length/7))===0||i===pts.length-1){ctx.beginPath();ctx.arc(p.x,p.y,2.5,0,Math.PI*2);ctx.fillStyle='#c7fff9';ctx.fill();}});
    ctx.font='8px system-ui';ctx.fillStyle='#68768c';ctx.textAlign='center';
    [0,Math.floor((series.length-1)/2),series.length-1].forEach((i)=>{if(series[i])ctx.fillText(String(series[i].day).slice(5),pts[i].x,h-5);});
  }
  function drawBars(canvas, entries, colors) {
    if(!canvas||!entries.length)return;const {ctx,w,h}=prepCanvas(canvas);const pad={l:9,r:7,t:8,b:20};const vals=entries.map(x=>Number(x[1]));const max=Math.max(1,...vals);const gap=7;const bw=(w-pad.l-pad.r-gap*(entries.length-1))/entries.length;
    entries.forEach(([label,value],i)=>{const barH=(Number(value)/max)*(h-pad.t-pad.b);const x=pad.l+i*(bw+gap);const y=h-pad.b-barH;const grad=ctx.createLinearGradient(0,y,0,h-pad.b);grad.addColorStop(0,colors[i%colors.length]);grad.addColorStop(1,'rgba(93,240,227,.25)');ctx.fillStyle=grad;ctx.beginPath();ctx.roundRect(x,y,bw,barH,4);ctx.fill();ctx.fillStyle='#738198';ctx.font='7px system-ui';ctx.textAlign='center';ctx.fillText(String(label).slice(0,7),x+bw/2,h-6);});
  }

  // Delegated interactions keep the UI small and all values rendered through escaped templates.
  document.addEventListener('click', async (event) => {
    const viewButton = event.target.closest('[data-view]');
    if (viewButton) { event.preventDefault(); setView(viewButton.dataset.view); return; }
    if (event.target.closest('[data-close-drawer]')) { closeDrawer(); return; }
    const threat = event.target.closest('[data-threat-id]');
    if (threat) { event.preventDefault(); await openThreat(threat.dataset.threatId); return; }
    const search = event.target.closest('[data-search-indicator]');
    if (search) { state.iocQuery=search.dataset.searchIndicator; state.lastIOC=null; setView('ioc'); return; }
    const technique = event.target.closest('[data-technique]');
    if (technique) { state.selectedTechnique=technique.dataset.technique; setView('attack'); return; }
    const openModule = event.target.closest('[data-open-module]');
    if (openModule) { state.openModule=openModule.dataset.openModule; setView('awareness'); return; }
    const moduleCard = event.target.closest('[data-module-card]');
    if (moduleCard) { state.openModule = state.openModule === moduleCard.dataset.moduleCard ? null : moduleCard.dataset.moduleCard; renderAwareness(); return; }
    const action = event.target.closest('[data-action]')?.dataset.action;
    if (!action) return;
    if (action==='refresh-view') renderView();
    if (action==='clear-filters') { state.filters={page:1,page_size:20,sort:'newest'}; renderThreats(); }
    if (action==='page-prev') { state.filters.page=Math.max(1,state.filters.page-1);renderThreats(); }
    if (action==='page-next') { state.filters.page++;renderThreats(); }
    if (action==='export-csv') exportCSV();
    if (action==='clear-technique') { state.selectedTechnique=null;renderAttack(); }
    if (action==='save-api-key') { const input=$('#api-key-input');state.apiKey=input?.value.trim()||''; if(state.apiKey)localStorage.setItem('signal-atlas-api-key',state.apiKey);else localStorage.removeItem('signal-atlas-api-key');toast('API key stored in this browser only.');renderGuide(); }
    if (action==='reset-browser-data' && STATIC_MODE) { for (let i=localStorage.length-1;i>=0;i--) { const key=localStorage.key(i); if (key?.startsWith('signal-atlas-static-')) localStorage.removeItem(key); } state.quizResult=null;state.lastQuiz=null;state.lastIOC=null;state.filters={page:1,page_size:20,sort:'newest'};toast('Local demo changes cleared in this browser.');renderGuide(); }
  });
  document.addEventListener('submit', async (event) => {
    if (event.target.id==='ioc-search-form') {event.preventDefault();const q=$('#ioc-query').value;lookupIOC(q);return;}
    if (event.target.id==='note-form') {event.preventDefault();const id=event.target.dataset.threatId;const note=$('#note-text').value.trim();if(note.length<3){toast('Add at least three non-space characters.','error');return;}try{await api(`/api/threats/${encodeURIComponent(id)}/notes`,{method:'POST',body:JSON.stringify({note})});toast(STATIC_MODE ? 'Analyst note saved in this browser.' : 'Analyst note saved to local SQLite.');await openThreat(id);}catch(error){toast(error.message,'error');}return;}
    if (event.target.id==='quiz-form') {event.preventDefault();const answers={};$$('.quiz-question',root).forEach((card)=>{const checked=$(`input[name="${card.dataset.question}"]:checked`,card);if(checked)answers[card.dataset.question]=Number(checked.value);});try{const result=await api('/api/quiz/submit',{method:'POST',body:JSON.stringify({answers})});state.quizResult=result;state.lastQuiz=result;toast(`Learning score recorded: ${result.overall_score}/100.`, 'ok','Self-reflection complete');await renderQuiz();window.scrollTo({top:0,behavior:'smooth'});}catch(error){toast(error.message,'error');}return;}
  });
  document.addEventListener('change', async (event) => {
    if(event.target.matches('#filter-severity,#filter-category,#filter-type,#filter-status,#filter-sort,#filter-date-from,#filter-date-to')){applyThreatFilters();return;}
    if(event.target.matches('#filter-risk,#filter-confidence')){const el=event.target;const output=$(`#${el.id==='filter-risk'?'risk-filter-value':'confidence-filter-value'}`);if(output)output.textContent=el.value;clearTimeout(window._filterTimer);window._filterTimer=setTimeout(applyThreatFilters,220);return;}
    if(event.target.matches('#threat-q')){applyThreatFilters();return;}
    if(event.target.matches('#vuln-severity')){state.vulnSeverity=event.target.value;renderVulnerabilities();return;}
    if(event.target.matches('#vuln-priority')){state.minPriority=Number(event.target.value);const output=$('#priority-filter-value');if(output)output.textContent=event.target.value;clearTimeout(window._vulnTimer);window._vulnTimer=setTimeout(renderVulnerabilities,220);return;}
    if(event.target.matches('#alert-filter')){state.alertFilter=event.target.value;renderAlerts();return;}
    if(event.target.matches('.alert-status-select')){const id=event.target.dataset.alertId,status=event.target.value;try{await api(`/api/alerts/${encodeURIComponent(id)}/status`,{method:'PUT',body:JSON.stringify({status})});toast(`Alert status changed to ${status}.`);if(state.view==='alerts')renderAlerts();}catch(error){toast(error.message,'error');}return;}
    if(event.target.matches('#threat-status-select')){const id=event.target.dataset.threatStatus,status=event.target.value;try{await api(`/api/threats/${encodeURIComponent(id)}`,{method:'PUT',body:JSON.stringify({status})});toast(`Threat workflow status changed to ${status}.`);await openThreat(id);}catch(error){toast(error.message,'error');}return;}
    if(event.target.matches('input[type="radio"]'))updateQuizProgress();
  });
  document.addEventListener('input', (event) => {
    if(event.target.matches('#filter-risk,#filter-confidence')){
      const output=$(`#${event.target.id==='filter-risk'?'risk-filter-value':'confidence-filter-value'}`);if(output)output.textContent=event.target.value;
    }
    if(event.target.matches('#vuln-priority')){const output=$('#priority-filter-value');if(output)output.textContent=event.target.value;}
  });
  $('#global-search').addEventListener('keydown',(event)=>{if(event.key==='Enter'){event.preventDefault();state.iocQuery=event.currentTarget.value.trim();state.lastIOC=null;setView('ioc');}});
  $('#refresh-button').addEventListener('click',async()=>{const button=$('#refresh-button');button.classList.add('spinning');try{state.stats=await api('/api/dashboard/stats');toast('Local threat records refreshed.');await renderView();}catch(error){toast(error.message,'error');}finally{button.classList.remove('spinning');}});
  document.addEventListener('keydown',(event)=>{if(event.key==='Escape'&&!$('#overlay').hidden)closeDrawer();if(event.key==='/'&&!event.target.matches('input,textarea,select')){$('#global-search').focus();event.preventDefault();}if(event.key==='Enter'&&event.target.matches('#threat-q'))applyThreatFilters();});
  window.addEventListener('resize',()=>{clearTimeout(window._chartResize);window._chartResize=setTimeout(drawAmbientCharts,120);});

  // Decorative background network: canvas-only, no remote resources or traffic.
  function initAmbient() {
    const canvas=$('#ambient-canvas'),ctx=canvas.getContext('2d');let width=0,height=0,points=[];const reduce=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    function resize(){const ratio=Math.min(2,window.devicePixelRatio||1);width=innerWidth;height=innerHeight;canvas.width=width*ratio;canvas.height=height*ratio;canvas.style.width=width+'px';canvas.style.height=height+'px';ctx.setTransform(ratio,0,0,ratio,0,0);points=Array.from({length:Math.min(58,Math.round(width/24))},()=>({x:Math.random()*width,y:Math.random()*height,vx:(Math.random()-.5)*.12,vy:(Math.random()-.5)*.12,r:Math.random()*1.2+.4,phase:Math.random()*Math.PI*2}));}
    function draw(time=0){ctx.clearRect(0,0,width,height);const drift=reduce?0:time*.00022;points.forEach((p,i)=>{if(!reduce){p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>width)p.vx*=-1;if(p.y<0||p.y>height)p.vy*=-1;}for(let j=i+1;j<points.length;j++){const q=points[j],dx=p.x-q.x,dy=p.y-q.y,d=Math.hypot(dx,dy);if(d<122){ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(q.x,q.y);ctx.strokeStyle=`rgba(74,196,202,${(1-d/122)*.07})`;ctx.lineWidth=.6;ctx.stroke();}}const alpha=.19+.12*Math.sin(drift+p.phase);ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.fillStyle=`rgba(113,224,221,${alpha})`;ctx.fill();});if(!reduce)requestAnimationFrame(draw);}
    resize();draw();window.addEventListener('resize',resize);
  }
  async function boot() {
    initAmbient();
    if (STATIC_MODE) {
      const feedLabel=$('.connection-state span:last-child'); if (feedLabel) feedLabel.textContent='GITHUB PAGES';
      const modeLabel=$('.side-system-top span:nth-child(2)'); if (modeLabel) modeLabel.textContent='STATIC BUILD';
      const modeTitle=$('.side-system-title'); if (modeTitle) modeTitle.textContent='Browser-only · no server calls';
      const modeCaption=$('.side-system-caption'); if (modeCaption) modeCaption.textContent='Bundled demo data · writes stay in localStorage';
    }
    const hash=location.hash.replace('#',''); if(viewTitles[hash])state.view=hash;
    $$('.nav-item[data-view]').forEach((button)=>button.classList.toggle('active',button.dataset.view===state.view));
    $('#view-kicker').textContent=viewTitles[state.view];
    try{state.stats=await api('/api/dashboard/stats');$('#nav-threat-count').textContent=num(state.stats.total_threat_records);const alertData=await api('/api/alerts?limit=500');$('#nav-alert-count').textContent=num(alertData.total_returned);}catch{}
    renderView();
  }
  boot();
})();
