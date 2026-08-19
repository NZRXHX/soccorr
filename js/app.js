/* ============================================================
   DXC SOC VULN CORRELATION — Main App
   SPA Router + Section Manager
   ============================================================ */
import { showToast, debounce, formatDate, buildCvssRing, buildBadge, cvssToSeverity, esc, downloadFile, delay } from './utils/helpers.js';
import { fetchCveById, searchCves, fetchRecentCves, parseCve, CWE_CATEGORIES } from './api/nvd.js';
import { loadAttackData, getGroups, parseTechnique, getTechniqueById, getMitigationsForTechnique, getSoftwareForTechnique } from './api/mitre.js';
import { parseRuleFile, compareRuleSets } from './parsers/rules.js';
import { runCorrelation, generateReport } from './sections/correlation.js';
import { renderCorrelationGraph, buildGraphData } from './utils/graph.js';

/* ── State ──────────────────────────────── */
const state = {
  currentSection: 'cve',
  attackData:     null,
  attackGroups:   null,
  cveResults:     [],
  cveTotal:       0,
  cveFilters:     { keyword: '', cvssMin: 0, cvssMax: 10, dateStart: '', dateEnd: '', cwe: '' },
  cveLoading:     false,
  aptSearch:      '',
  aptSelected:    null,
  selectedTtp:    null,
  rulesFile:      null,
  rulesData:      null,
  compareA:       null,
  compareB:       null,
  corrFile:       null,
  corrRules:      null,
  corrResults:    null,
  corrMode:       'advanced',
  sidebarCollapsed: false,
  destroyGraph:   null,
};

/* ── Init ───────────────────────────────── */
document.addEventListener('DOMContentLoaded', init);

async function init() {
  setupSidebar();
  setupNav();
  setupModals();
  await navigateTo('home');

  // Preload ATT&CK data in background
  setTimeout(() => {
    loadAttackData()
      .then(data => {
        state.attackData  = data;
        state.attackGroups = getGroups(data);
        updateTopbarBadge('ATT&CK Loaded', true);
      })
      .catch(() => updateTopbarBadge('ATT&CK Offline', false));
  }, 800);
}

function updateTopbarBadge(text, ok) {
  const badge = document.getElementById('mitre-badge');
  if (badge) {
    badge.innerHTML = `<span class="status-dot" style="${ok ? '' : 'background:#c62828'}"></span>${text}`;
  }
}

/* ── Sidebar ────────────────────────────── */
function setupSidebar() {
  const sidebar = document.getElementById('sidebar');
  const toggleBtn = document.getElementById('sidebar-toggle');
  toggleBtn?.addEventListener('click', () => {
    state.sidebarCollapsed = !state.sidebarCollapsed;
    sidebar.classList.toggle('collapsed', state.sidebarCollapsed);
    toggleBtn.textContent = state.sidebarCollapsed ? '▶' : '◀';
  });
}

/* ── Navigation ─────────────────────────── */
function setupNav() {
  document.querySelectorAll('.nav-item[data-section]').forEach(item => {
    item.addEventListener('click', () => navigateTo(item.dataset.section));
  });
}

async function navigateTo(sectionId) {
  state.currentSection = sectionId;
  document.querySelectorAll('.section-page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));

  const page    = document.getElementById(`section-${sectionId}`);
  const navItem = document.querySelector(`.nav-item[data-section="${sectionId}"]`);
  if (page)    page.classList.add('active');
  if (navItem) navItem.classList.add('active');

  updateBreadcrumb(sectionId);

  // Lazy-init sections
  const inits = {
    home:        initHome,
    cve:         initCve,
    apt:         initApt,
    rules:       initRules,
    correlation: initCorrelation,
    examples:    initExamples,
  };
  await inits[sectionId]?.();
}

function updateBreadcrumb(section) {
  const labels = {
    home: 'Dashboard', cve: 'CVE Intelligence', apt: 'APT Groups & TTPs',
    rules: 'SOC/SIEM Rules', correlation: 'Rule Correlation', examples: 'Example Files',
  };
  const el = document.getElementById('breadcrumb-current');
  if (el) el.textContent = labels[section] ?? section;
}

/* ── HOME section ───────────────────────── */
async function initHome() {
  // Just ensure the welcome dashboard is visible
}

/* ── CVE SECTION ────────────────────────── */
let cveInitialized = false;

async function initCve() {
  if (cveInitialized) return;
  cveInitialized = true;

  // Populate CWE dropdown
  const cweSelect = document.getElementById('cve-cwe-filter');
  if (cweSelect) {
    cweSelect.innerHTML = CWE_CATEGORIES.map(c =>
      `<option value="${esc(c.id)}">${esc(c.label)}</option>`
    ).join('');
  }

  // Wire up controls
  const searchInput = document.getElementById('cve-search-input');
  const cvssMin     = document.getElementById('cvss-min');
  const cvssMax     = document.getElementById('cvss-max');
  const dateStart   = document.getElementById('cve-date-start');
  const dateEnd     = document.getElementById('cve-date-end');
  const searchBtn   = document.getElementById('cve-search-btn');
  const recentBtn   = document.getElementById('cve-recent-btn');

  const doSearch = debounce(runCveSearch, 500);

  searchInput?.addEventListener('input', e => { state.cveFilters.keyword = e.target.value; doSearch(); });
  cweSelect?.addEventListener('change', e => { state.cveFilters.cwe = e.target.value; doSearch(); });
  cvssMin?.addEventListener('input', e => {
    state.cveFilters.cvssMin = parseFloat(e.target.value);
    document.getElementById('cvss-min-val').textContent = e.target.value;
    doSearch();
  });
  cvssMax?.addEventListener('input', e => {
    state.cveFilters.cvssMax = parseFloat(e.target.value);
    document.getElementById('cvss-max-val').textContent = e.target.value;
    doSearch();
  });
  dateStart?.addEventListener('change', e => { state.cveFilters.dateStart = e.target.value; doSearch(); });
  dateEnd?.addEventListener('change',   e => { state.cveFilters.dateEnd   = e.target.value; doSearch(); });
  searchBtn?.addEventListener('click', runCveSearch);
  recentBtn?.addEventListener('click', loadRecentCves);

  // Load recent CVEs on init
  await loadRecentCves();
}

async function loadRecentCves() {
  // Reset filter state
  state.cveFilters = { keyword: '', cvssMin: 0, cvssMax: 10, dateStart: '', dateEnd: '', cwe: '' };

  // Reset UI filter controls
  const searchInput = document.getElementById('cve-search-input');
  const cweSelect   = document.getElementById('cve-cwe-filter');
  const cvssMin     = document.getElementById('cvss-min');
  const cvssMax     = document.getElementById('cvss-max');
  const cvssMinVal  = document.getElementById('cvss-min-val');
  const cvssMaxVal  = document.getElementById('cvss-max-val');
  const dateStart   = document.getElementById('cve-date-start');
  const dateEnd     = document.getElementById('cve-date-end');

  if (searchInput) searchInput.value = '';
  if (cweSelect)   cweSelect.value   = '';
  if (cvssMin)     cvssMin.value     = '0';
  if (cvssMax)     cvssMax.value     = '10';
  if (cvssMinVal)  cvssMinVal.textContent = '0';
  if (cvssMaxVal)  cvssMaxVal.textContent = '10';
  if (dateStart)   dateStart.value   = '';
  if (dateEnd)     dateEnd.value     = '';

  showCveLoading(true);
  try {
    const result = await fetchRecentCves(40);
    state.cveResults = result.items;
    state.cveTotal   = result.total;
    renderCveGrid(state.cveResults);
    updateCveStats(result.total);
    showToast('Loaded Recent CVEs', 'success');
  } catch (err) {
    showCveError(err.message);
  } finally {
    showCveLoading(false);
  }
}

async function runCveSearch() {
  if (state.cveLoading) return;
  showCveLoading(true);
  const f = state.cveFilters;
  try {
    const opts = {
      keyword:  f.keyword || undefined,
      cvssMin:  f.cvssMin > 0 ? f.cvssMin : undefined,
      cvssMax:  f.cvssMax < 10 ? f.cvssMax : undefined,
      dateStart: f.dateStart || undefined,
      dateEnd:   f.dateEnd   || undefined,
      cweId:    f.cwe || undefined,
      resultsPerPage: 40,
    };

    // Direct CVE ID lookup
    if (/^CVE-\d{4}-\d+$/i.test(f.keyword?.trim())) {
      const raw = await fetchCveById(f.keyword.trim());
      const parsed = raw ? (raw.id ? raw : parseCve(raw)) : null;
      state.cveResults = parsed ? [parsed] : [];
      renderCveGrid(state.cveResults);
      updateCveStats(state.cveResults.length);
      return;
    }

    const result = await searchCves(opts);
    state.cveResults = result.items;
    state.cveTotal   = result.total;
    renderCveGrid(state.cveResults);
    updateCveStats(result.total);
  } catch (err) {
    showCveError(err.message);
    showToast(err.message, 'error');
  } finally {
    showCveLoading(false);
  }
}

function renderCveGrid(cves) {
  const grid = document.getElementById('cve-grid');
  if (!grid) return;
  if (!cves.length) {
    grid.innerHTML = `
      <div class="empty-state" style="grid-column:1/-1">
        <div class="empty-state-icon">🔍</div>
        <div class="empty-state-title">No CVEs found</div>
        <div class="empty-state-subtitle">Try adjusting your search filters</div>
      </div>`;
    return;
  }
  grid.innerHTML = cves.map(cve => buildCveCard(cve)).join('');
  grid.querySelectorAll('.cve-card').forEach((card, i) => {
    card.addEventListener('click', () => openCveModal(cves[i]));
  });
}

function buildCveCard(cve) {
  const sev   = cve.severity ?? 'info';
  const score = cve.score != null ? cve.score.toFixed(1) : 'N/A';
  return `
    <div class="cve-card clickable">
      <div class="cve-card-top">
        ${buildCvssRing(cve.score ?? 0)}
        <div style="flex:1;overflow:hidden">
          <div class="cve-id">${esc(cve.id)}</div>
          <div style="display:flex;gap:6px;margin-top:4px;flex-wrap:wrap">
            ${buildBadge(sev.toUpperCase(), sev)}
            ${cve.cwes.slice(0, 2).map(c => `<span class="badge badge-neutral">${esc(c)}</span>`).join('')}
          </div>
        </div>
      </div>
      <div class="cve-card-body">
        <p class="cve-description">${esc(cve.description)}</p>
      </div>
      <div class="cve-card-footer">
        <span class="cve-date">📅 ${formatDate(cve.published)}</span>
        ${cve.vulnStatus ? `<span class="badge badge-neutral">${esc(cve.vulnStatus)}</span>` : ''}
      </div>
    </div>`;
}

function openCveModal(cve) {
  const modal   = document.getElementById('cve-modal');
  const content = document.getElementById('cve-modal-content');
  if (!modal || !content) return;

  const sev = cve.severity ?? 'info';
  content.innerHTML = `
    <div class="modal-header">
      <div>
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px">
          <span class="cve-id" style="font-size:1.25rem">${esc(cve.id)}</span>
          ${buildBadge(sev.toUpperCase(), sev)}
        </div>
        <div style="font-size:13px;color:var(--grey-500)">
          Published: ${formatDate(cve.published)} &nbsp;|&nbsp; Modified: ${formatDate(cve.lastModified)}
          &nbsp;|&nbsp; Status: ${esc(cve.vulnStatus ?? 'N/A')}
        </div>
      </div>
      <button class="btn btn-ghost btn-icon modal-close" onclick="closeModal('cve-modal')">✕</button>
    </div>
    <div class="modal-body">
      <p style="color:var(--grey-700);line-height:1.7;margin-bottom:24px">${esc(cve.description)}</p>
      <div class="cve-detail-grid">
        <div class="cvss-detail-card">
          <div style="font-weight:700;margin-bottom:12px;color:var(--grey-800)">📊 CVSS Score</div>
          <div style="display:flex;align-items:center;gap:16px;margin-bottom:8px">
            ${buildCvssRing(cve.score ?? 0)}
            <div>
              <div style="font-size:2rem;font-weight:800;color:var(--dxc-purple)">${cve.score?.toFixed(1) ?? 'N/A'}</div>
              <div style="font-size:12px;color:var(--grey-500)">Base Score (CVSS v3)</div>
            </div>
          </div>
          ${cve.vector ? `<div class="cvss-vector">${esc(cve.vector)}</div>` : ''}
        </div>
        <div>
          <div style="font-weight:700;margin-bottom:12px;color:var(--grey-800)">🔗 Weakness Types</div>
          <div class="tag-list">
            ${cve.cwes.map(c => `<span class="tag">${esc(c)}</span>`).join('') || '<span class="tag grey">None listed</span>'}
          </div>
          ${cve.cpes.length ? `
            <div style="font-weight:700;margin:16px 0 8px;color:var(--grey-800)">💻 Affected Systems</div>
            <div style="display:flex;flex-direction:column;gap:4px">
              ${cve.cpes.slice(0, 6).map(c => `<span style="font-family:var(--font-mono);font-size:11px;color:var(--grey-600)">${esc(c)}</span>`).join('')}
              ${cve.cpes.length > 6 ? `<span style="font-size:11px;color:var(--grey-400)">+${cve.cpes.length - 6} more</span>` : ''}
            </div>` : ''}
        </div>
      </div>
      ${cve.references.length ? `
        <div>
          <div style="font-weight:700;margin-bottom:10px;color:var(--grey-800)">🔗 References</div>
          ${cve.references.map(r => `
            <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--grey-100)">
              <a href="${esc(r.url)}" target="_blank" rel="noopener" style="font-size:13px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.url)}</a>
              ${r.tags.map(t => `<span class="badge badge-neutral">${esc(t)}</span>`).join('')}
            </div>`).join('')}
        </div>` : ''}
    </div>
    <div class="modal-footer">
      <a href="https://nvd.nist.gov/vuln/detail/${esc(cve.id)}" target="_blank" class="btn btn-secondary">View on NVD ↗</a>
      <button class="btn btn-ghost" onclick="closeModal('cve-modal')">Close</button>
    </div>`;

  modal.classList.add('open');
}

function showCveLoading(loading) {
  state.cveLoading = loading;
  const grid = document.getElementById('cve-grid');
  if (loading && grid) {
    grid.innerHTML = Array(6).fill(0).map(() => `
      <div class="card">
        <div class="card-body">
          <div class="skeleton skeleton-text wide" style="margin-bottom:8px"></div>
          <div class="skeleton skeleton-text narrow" style="margin-bottom:16px"></div>
          <div class="skeleton skeleton-text" style="margin-bottom:6px"></div>
          <div class="skeleton skeleton-text" style="margin-bottom:6px"></div>
          <div class="skeleton skeleton-text narrow"></div>
        </div>
      </div>`).join('');
  }
}

function showCveError(msg) {
  const grid = document.getElementById('cve-grid');
  if (grid) grid.innerHTML = `
    <div class="empty-state" style="grid-column:1/-1">
      <div class="empty-state-icon">⚠️</div>
      <div class="empty-state-title">API Error</div>
      <div class="empty-state-subtitle">${esc(msg)}</div>
    </div>`;
}

function updateCveStats(total) {
  const el = document.getElementById('cve-total-count');
  if (el) el.textContent = total.toLocaleString();
}

/* ── APT SECTION ────────────────────────── */
let aptInitialized = false;

async function initApt() {
  if (aptInitialized) return;
  aptInitialized = true;

  const listEl    = document.getElementById('apt-list');
  const searchEl  = document.getElementById('apt-search');
  const detailEl  = document.getElementById('apt-detail');

  // Show loading
  if (listEl) listEl.innerHTML = `<div class="loading-state"><div class="spinner"></div><div>Loading ATT&CK data…</div></div>`;

  try {
    if (!state.attackData) {
      state.attackData  = await loadAttackData();
      state.attackGroups = getGroups(state.attackData);
    }
    if (!state.attackGroups) {
      state.attackGroups = getGroups(state.attackData);
    }

    document.getElementById('apt-total-count')?.setAttribute('data-total', state.attackGroups.length);
    document.getElementById('apt-count-stat').textContent = state.attackGroups.length;

    renderAptList(state.attackGroups);

    searchEl?.addEventListener('input', debounce(e => {
      state.aptSearch = e.target.value.toLowerCase();
      const filtered  = state.attackGroups.filter(g =>
        g.name.toLowerCase().includes(state.aptSearch) ||
        g.aliases.some(a => a.toLowerCase().includes(state.aptSearch)) ||
        g.id?.toLowerCase().includes(state.aptSearch)
      );
      renderAptList(filtered);
    }, 300));

  } catch (err) {
    if (listEl) listEl.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚠️</div><div class="empty-state-title">Failed to load ATT&CK data</div><div class="empty-state-subtitle">${esc(err.message)}</div></div>`;
    showToast('Failed to load MITRE ATT&CK data. Check internet connection.', 'error');
  }
}

function renderAptList(groups) {
  const listEl = document.getElementById('apt-list');
  if (!listEl) return;
  if (!groups.length) {
    listEl.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🔍</div><div class="empty-state-title">No groups found</div></div>`;
    return;
  }
  listEl.innerHTML = groups.map(g => `
    <div class="apt-list-item" data-id="${esc(g.id)}" onclick="selectApt('${esc(g.id)}')">
      <div class="apt-avatar">${g.name.slice(0, 2).toUpperCase()}</div>
      <div>
        <div class="apt-list-name">${esc(g.name)}</div>
        <div class="apt-list-meta">${esc(g.id)} ${g.aliases.length ? '· ' + g.aliases.slice(0, 2).join(', ') : ''}</div>
      </div>
      <div class="apt-list-count">${g.techniqueCount}</div>
    </div>`).join('');
}

window.selectApt = function(groupId) {
  const group = state.attackGroups?.find(g => g.id === groupId);
  if (!group) return;
  state.aptSelected = group;

  document.querySelectorAll('.apt-list-item').forEach(el =>
    el.classList.toggle('active', el.dataset.id === groupId));

  const layout    = document.getElementById('apt-layout');
  const detailEl  = document.getElementById('apt-detail');
  layout?.classList.add('split');
  if (detailEl) {
    detailEl.innerHTML = buildAptDetail(group);
    detailEl.style.display = 'block';
  }
};

function buildAptDetail(group) {
  const tacticGroups = {};
  for (const tech of group.techniques) {
    for (const tactic of (tech.tactics ?? ['Unknown'])) {
      if (!tacticGroups[tactic]) tacticGroups[tactic] = [];
      tacticGroups[tactic].push(tech);
    }
  }

  return `
    <div class="apt-detail-hero">
      <div style="font-size:12px;font-weight:600;opacity:0.7;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px">${esc(group.id)}</div>
      <div class="apt-detail-name">${esc(group.name)}</div>
      <div class="apt-detail-aliases">${group.aliases.length ? 'Also known as: ' + group.aliases.slice(0, 5).map(a => esc(a)).join(', ') : 'No known aliases'}</div>
      <div class="apt-detail-meta-row">
        <div class="apt-meta-chip">🎯 ${group.techniqueCount} Techniques</div>
        ${group.url ? `<a href="${esc(group.url)}" target="_blank" class="apt-meta-chip" style="color:white;text-decoration:none">🔗 ATT&CK Page ↗</a>` : ''}
        <div class="apt-meta-chip">📋 ${Object.keys(tacticGroups).length} Tactics</div>
      </div>
    </div>
    <div class="apt-detail-body">
      ${group.description ? `<p style="color:var(--grey-700);margin-bottom:24px;line-height:1.7;font-size:0.9rem">${esc(group.description.slice(0, 600))}${group.description.length > 600 ? '…' : ''}</p>` : ''}
      ${Object.entries(tacticGroups).map(([tactic, techs]) => `
        <div style="margin-bottom:24px">
          <div style="font-weight:700;color:var(--dxc-purple);font-size:0.85rem;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:12px;display:flex;align-items:center;gap:8px">
            <span style="width:8px;height:8px;border-radius:50%;background:var(--dxc-purple);flex-shrink:0"></span>
            ${esc(tactic)}
            <span style="font-weight:500;color:var(--grey-500);font-size:11px;text-transform:none;letter-spacing:0">(${techs.length})</span>
          </div>
          <div class="ttp-grid">
            ${techs.map(t => `
              <div class="ttp-card" onclick="openTtpModal('${esc(t.id)}')">
                <div class="ttp-id">${esc(t.id)}</div>
                <div class="ttp-name">${esc(t.name)}</div>
                <div class="ttp-tactic">${t.platforms?.slice(0, 3).join(', ') ?? ''}</div>
              </div>`).join('')}
          </div>
        </div>`).join('')}
    </div>`;
}

window.openTtpModal = function(techId) {
  if (!state.attackData) return;
  const tech        = getTechniqueById(state.attackData, techId);
  if (!tech) return;
  const mitigations = getMitigationsForTechnique(state.attackData, tech.stixId);
  const software    = getSoftwareForTechnique(state.attackData, tech.stixId);

  const modal   = document.getElementById('ttp-modal');
  const content = document.getElementById('ttp-modal-content');
  if (!modal || !content) return;

  content.innerHTML = `
    <div class="modal-header">
      <div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
          <span style="font-family:var(--font-mono);font-weight:700;color:var(--dxc-purple);font-size:1rem">${esc(tech.id)}</span>
          ${tech.isSubTechnique ? buildBadge('Sub-Technique', 'purple') : ''}
        </div>
        <div style="font-size:1.2rem;font-weight:700;color:var(--grey-900)">${esc(tech.name)}</div>
      </div>
      <button class="btn btn-ghost btn-icon" onclick="closeModal('ttp-modal')">✕</button>
    </div>
    <div class="modal-body">
      <div class="tag-list" style="margin-bottom:16px">
        ${tech.tactics.map(t => `<span class="badge badge-purple">${esc(t)}</span>`).join('')}
        ${tech.platforms.slice(0, 4).map(p => `<span class="badge badge-neutral">${esc(p)}</span>`).join('')}
      </div>
      <p style="color:var(--grey-700);line-height:1.7;margin-bottom:20px">${esc(tech.description?.slice(0, 600) ?? '')}${(tech.description?.length ?? 0) > 600 ? '…' : ''}</p>
      
      ${tech.detection ? `
        <div style="background:var(--severity-info-bg);border:1px solid var(--severity-info-border);border-radius:var(--radius-md);padding:16px;margin-bottom:16px">
          <div style="font-weight:700;color:var(--severity-info);margin-bottom:8px">🔍 Detection</div>
          <p style="font-size:13px;color:var(--grey-700);line-height:1.6">${esc(tech.detection.slice(0, 400))}${tech.detection.length > 400 ? '…' : ''}</p>
        </div>` : ''}

      ${tech.dataSources.length ? `
        <div style="margin-bottom:16px">
          <div style="font-weight:700;margin-bottom:8px">📡 Data Sources</div>
          <div class="tag-list">${tech.dataSources.slice(0, 8).map(ds => `<span class="tag grey">${esc(ds)}</span>`).join('')}</div>
        </div>` : ''}

      ${mitigations.length ? `
        <div style="margin-bottom:16px">
          <div style="font-weight:700;margin-bottom:8px">🛡️ Mitigations (${mitigations.length})</div>
          ${mitigations.slice(0, 4).map(m => `
            <div style="border:1px solid var(--severity-low-border);background:var(--severity-low-bg);border-radius:var(--radius-md);padding:10px 14px;margin-bottom:8px">
              <div style="font-weight:600;font-size:13px;margin-bottom:4px">${esc(m.name)}</div>
              <div style="font-size:12px;color:var(--grey-600)">${esc(m.description.slice(0, 200))}</div>
            </div>`).join('')}
        </div>` : ''}

      ${software.length ? `
        <div>
          <div style="font-weight:700;margin-bottom:8px">🦠 Associated Malware/Tools</div>
          <div class="tag-list">${software.slice(0, 10).map(s =>
            `<span class="badge ${s.type === 'malware' ? 'badge-critical' : 'badge-neutral'}">${esc(s.name)}</span>`).join('')}
          </div>
        </div>` : ''}
    </div>
    <div class="modal-footer">
      ${tech.url ? `<a href="${esc(tech.url)}" target="_blank" class="btn btn-secondary">View on ATT&CK ↗</a>` : ''}
      <button class="btn btn-ghost" onclick="closeModal('ttp-modal')">Close</button>
    </div>`;

  modal.classList.add('open');
};

/* ── RULES SECTION ──────────────────────── */
let rulesInitialized = false;

function initRules() {
  if (rulesInitialized) return;
  rulesInitialized = true;

  // Tab switching
  document.querySelectorAll('#section-rules .tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#section-rules .tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('#section-rules .tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab)?.classList.add('active');
    });
  });

  // Visualizer upload
  setupDropzone('rules-dropzone', 'rules-file-input', handleRulesUpload);
  // Comparator uploads
  setupDropzone('compare-dropzone-a', 'compare-file-a', f => handleCompareUpload(f, 'a'));
  setupDropzone('compare-dropzone-b', 'compare-file-b', f => handleCompareUpload(f, 'b'));
}

function setupDropzone(zoneId, inputId, handler) {
  const zone  = document.getElementById(zoneId);
  const input = document.getElementById(inputId);
  if (!zone || !input) return;
  input.addEventListener('change', e => { if (e.target.files[0]) handler(e.target.files[0]); });
  zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', e => { zone.classList.remove('drag-over'); });
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) handler(file);
  });
}

async function handleRulesUpload(file) {
  const content = await readFile(file);
  const result  = parseRuleFile(content, file.name);
  state.rulesData = result;
  if (result.error) {
    showToast(`Parse error: ${result.error}`, 'error');
    return;
  }
  showToast(`Loaded ${result.rules.filter(Boolean).length} rules (${result.format})`, 'success');
  renderRulesVisualizer(result);
}

function renderRulesVisualizer(result) {
  const container = document.getElementById('rules-visualizer-output');
  if (!container) return;
  const validRules = result.rules.filter(Boolean);
  const stats = {
    critical: validRules.filter(r => r.severity === 'critical').length,
    high:     validRules.filter(r => r.severity === 'high').length,
    medium:   validRules.filter(r => r.severity === 'medium').length,
    low:      validRules.filter(r => r.severity === 'low').length,
  };

  container.innerHTML = `
    <div class="rules-panel">
      <div class="rules-panel-header">
        <div>
          <div style="font-weight:700;font-size:1rem">${esc(result.format)} Rules</div>
          <div style="font-size:13px;color:var(--grey-500)">${validRules.length} rules loaded</div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${Object.entries(stats).filter(([k,v]) => v > 0).map(([k,v]) => `<span class="badge badge-${k}">${v} ${k}</span>`).join('')}
        </div>
      </div>
      <div style="padding:16px">
        ${validRules.map((r, i) => buildRuleCard(r, i)).join('')}
      </div>
    </div>`;

  // Wire expand/collapse
  container.querySelectorAll('.rule-card-header').forEach(h => {
    h.addEventListener('click', () => {
      h.closest('.rule-card')?.classList.toggle('expanded');
    });
  });
}

function buildRuleCard(r, idx) {
  if (!r) return '';
  return `
    <div class="rule-card" id="rule-card-${idx}">
      <div class="rule-card-header">
        <span class="rule-expand-icon">▶</span>
        <div class="rule-name">${esc(r.name)}</div>
        <div style="display:flex;gap:6px;align-items:center;flex-shrink:0">
          ${buildBadge(r.severity?.toUpperCase() ?? 'UNKNOWN', r.severity ?? 'info')}
          <span class="rule-format-chip">${esc(r.format)}</span>
        </div>
      </div>
      <div class="rule-card-body">
        ${r.description ? `<p style="font-size:13px;color:var(--grey-600);margin-bottom:12px">${esc(r.description)}</p>` : ''}
        <div class="rule-detail-grid">
          <div>
            <div style="font-size:11px;font-weight:600;color:var(--grey-500);text-transform:uppercase;margin-bottom:6px">Techniques</div>
            <div class="tag-list">
              ${r.techniques.length ? r.techniques.map(t => `<span class="tag">${esc(t)}</span>`).join('') : '<span class="tag grey">None</span>'}
            </div>
          </div>
          <div>
            <div style="font-size:11px;font-weight:600;color:var(--grey-500);text-transform:uppercase;margin-bottom:6px">Tactics</div>
            <div class="tag-list">
              ${r.tactics.length ? r.tactics.map(t => `<span class="tag grey">${esc(t)}</span>`).join('') : '<span class="tag grey">None</span>'}
            </div>
          </div>
        </div>
        ${r.cves.length ? `<div style="margin-top:12px"><div style="font-size:11px;font-weight:600;color:var(--grey-500);text-transform:uppercase;margin-bottom:6px">CVEs</div><div class="tag-list">${r.cves.map(c => `<span class="badge badge-high">${esc(c)}</span>`).join('')}</div></div>` : ''}
        ${r.query ? `<div style="margin-top:12px"><div style="font-size:11px;font-weight:600;color:var(--grey-500);text-transform:uppercase;margin-bottom:6px">Detection Logic</div><div class="code-block">${esc(r.query.slice(0, 600))}${r.query.length > 600 ? '\n…' : ''}</div></div>` : ''}
        <div style="margin-top:12px;display:flex;gap:12px;font-size:12px;color:var(--grey-500)">
          <span>Platform: <strong>${esc(r.platform)}</strong></span>
          <span>Risk: <strong>${r.riskScore}</strong></span>
          <span>Status: <strong>${esc(String(r.status))}</strong></span>
        </div>
      </div>
    </div>`;
}

/* Compare mode */
async function handleCompareUpload(file, slot) {
  const content = await readFile(file);
  const result  = parseRuleFile(content, file.name);
  if (result.error) { showToast(`Parse error: ${result.error}`, 'error'); return; }
  if (slot === 'a') state.compareA = { result, filename: file.name };
  else              state.compareB = { result, filename: file.name };

  const zone = document.getElementById(slot === 'a' ? 'compare-dropzone-a' : 'compare-dropzone-b');
  if (zone) {
    zone.classList.add('loaded');
    zone.querySelector('.dropzone-title').textContent = file.name;
    zone.querySelector('.dropzone-subtitle').textContent = `${result.rules.filter(Boolean).length} rules • ${result.format}`;
  }
  showToast(`File ${slot.toUpperCase()} loaded: ${result.rules.filter(Boolean).length} rules`, 'success');

  if (state.compareA && state.compareB) {
    runComparison();
  }
}

function runComparison() {
  const { compareA, compareB } = state;
  if (!compareA || !compareB) return;
  const diff = compareRuleSets(
    compareA.result.rules.filter(Boolean),
    compareB.result.rules.filter(Boolean),
    compareA.filename,
    compareB.filename
  );
  renderDiffResults(diff);
}

function renderDiffResults(diff) {
  const container = document.getElementById('compare-results');
  if (!container) return;
  container.style.display = 'block';
  const { stats } = diff;
  container.innerHTML = `
    <div class="diff-results">
      <div class="diff-summary">
        <div class="diff-stat common">
          <div class="diff-stat-value">${stats.commonCount}</div>
          <div class="diff-stat-label">✅ Common Rules</div>
        </div>
        <div class="diff-stat only-a">
          <div class="diff-stat-value">${stats.onlyACount}</div>
          <div class="diff-stat-label">🔵 Only in A</div>
        </div>
        <div class="diff-stat only-b">
          <div class="diff-stat-value">${stats.onlyBCount}</div>
          <div class="diff-stat-label">🟣 Only in B</div>
        </div>
        <div class="diff-stat modified">
          <div class="diff-stat-value">${stats.modifiedCount}</div>
          <div class="diff-stat-label">🟡 Different Logic</div>
        </div>
      </div>
      <div style="padding:20px;border-bottom:1px solid var(--grey-200)">
        <div style="font-weight:700;margin-bottom:8px">Overlap</div>
        <div class="progress-bar"><div class="progress-fill" style="width:${stats.overlapPct}%"></div></div>
        <div style="font-size:12px;color:var(--grey-500);margin-top:4px">${stats.overlapPct}% rule overlap between the two files</div>
      </div>
      <div class="diff-rules-list">
        ${diff.common.map(d => `<div class="diff-rule-item common"><span class="diff-rule-icon">✅</span><span class="diff-rule-name">${esc(d.ruleA.name)}</span><span class="diff-rule-source">${esc(d.ruleA.format)}</span></div>`).join('')}
        ${diff.onlyA.map(r => `<div class="diff-rule-item only-a"><span class="diff-rule-icon">🔵</span><span class="diff-rule-name">${esc(r.name)}</span><span class="diff-rule-source">Only in A</span></div>`).join('')}
        ${diff.onlyB.map(r => `<div class="diff-rule-item only-b"><span class="diff-rule-icon">🟣</span><span class="diff-rule-name">${esc(r.name)}</span><span class="diff-rule-source">Only in B</span></div>`).join('')}
        ${diff.modified.map(d => `<div class="diff-rule-item modified"><span class="diff-rule-icon">🟡</span><span class="diff-rule-name">${esc(d.ruleA.name)}</span><span class="diff-rule-source">Different logic/severity</span></div>`).join('')}
      </div>
    </div>`;
}

/* ── CORRELATION SECTION ────────────────── */
let corrInitialized = false;

function initCorrelation() {
  if (corrInitialized) return;
  corrInitialized = true;

  setupDropzone('corr-dropzone', 'corr-file-input', handleCorrUpload);

  // Scan mode selection
  document.querySelectorAll('.scan-mode-card').forEach(card => {
    card.addEventListener('click', () => {
      document.querySelectorAll('.scan-mode-card').forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      state.corrMode = card.dataset.mode;
      card.querySelector('input[type="radio"]').checked = true;
    });
  });

  document.getElementById('run-correlation-btn')?.addEventListener('click', startCorrelation);
  document.getElementById('export-report-btn')?.addEventListener('click', exportReport);
}

async function handleCorrUpload(file) {
  const content = await readFile(file);
  const result  = parseRuleFile(content, file.name);
  if (result.error) { showToast(`Parse error: ${result.error}`, 'error'); return; }
  state.corrRules = result.rules.filter(Boolean);
  state.corrFile  = file.name;

  const zone = document.getElementById('corr-dropzone');
  if (zone) {
    zone.classList.add('drag-over');
    zone.style.borderStyle = 'solid';
    zone.querySelector('.dropzone-title').textContent = file.name;
    zone.querySelector('.dropzone-subtitle').textContent = `${state.corrRules.length} rules • ${result.format} — Ready to correlate`;
  }
  document.getElementById('run-correlation-btn').disabled = false;
  showToast(`${state.corrRules.length} ${result.format} rules loaded`, 'success');
}

async function startCorrelation() {
  if (!state.corrRules?.length) { showToast('Please upload a rule file first', 'warning'); return; }

  const progressEl = document.getElementById('scan-progress');
  const resultsEl  = document.getElementById('correlation-results');
  progressEl?.classList.add('visible');
  resultsEl?.classList.remove('visible');

  const stepsEl = document.getElementById('scan-steps-list');
  const steps   = [];

  function onProgress({ step, total, label }) {
    if (!stepsEl) return;
    // Add step
    const div = document.createElement('div');
    div.className = 'scan-step running';
    div.id = `step-${step}`;
    div.innerHTML = `<div class="scan-step-dot">⟳</div><div class="scan-step-label">${esc(label)}</div>`;
    stepsEl.appendChild(div);
    // Mark previous as done
    if (step > 1) {
      const prev = document.getElementById(`step-${step - 1}`);
      if (prev) { prev.classList.remove('running'); prev.classList.add('done'); prev.querySelector('.scan-step-dot').textContent = '✓'; }
    }
  }

  if (stepsEl) stepsEl.innerHTML = '';

  try {
    const results = await runCorrelation(state.corrRules, state.corrMode, onProgress);
    state.corrResults = results;

    // Mark last step done
    const lastStep = stepsEl?.lastElementChild;
    if (lastStep) { lastStep.classList.remove('running'); lastStep.classList.add('done'); lastStep.querySelector('.scan-step-dot').textContent = '✓'; }

    await delay(600);
    progressEl?.classList.remove('visible');
    renderCorrelationResults(results);
  } catch (err) {
    showToast('Correlation failed: ' + err.message, 'error');
    progressEl?.classList.remove('visible');
  }
}

function renderCorrelationResults(results) {
  const resultsEl = document.getElementById('correlation-results');
  if (!resultsEl) return;
  resultsEl.classList.add('visible');

  // Summary stats
  const weak    = results.filter(r => r.overallScore < 0.3);
  const partial = results.filter(r => r.overallScore >= 0.3 && r.overallScore < 0.65);
  const strong  = results.filter(r => r.overallScore >= 0.65);

  document.getElementById('corr-weak-count').textContent    = weak.length;
  document.getElementById('corr-partial-count').textContent = partial.length;
  document.getElementById('corr-strong-count').textContent  = strong.length;

  // Render summary lists
  renderSummaryList('corr-weak-list',    weak,    'critical');
  renderSummaryList('corr-partial-list', partial, 'high');
  renderSummaryList('corr-strong-list',  strong,  'low');

  // Graph
  if (state.destroyGraph) { state.destroyGraph(); state.destroyGraph = null; }
  const graphData = buildGraphData(results);
  state.destroyGraph = renderCorrelationGraph('correlation-graph', graphData, node => {
    document.getElementById('graph-node-detail').innerHTML = buildNodeDetail(node);
    document.getElementById('graph-node-panel').style.display = 'block';
  });

  document.getElementById('export-report-btn').disabled = false;
}

function renderSummaryList(containerId, results, severityClass) {
  const el = document.getElementById(containerId);
  if (!el) return;
  if (!results.length) { el.innerHTML = '<div style="padding:12px 20px;font-size:13px;color:var(--grey-400)">None</div>'; return; }
  el.innerHTML = results.map(r => `
    <div class="summary-rule-item">
      <div class="rule-indicator" style="background:var(--severity-${severityClass})"></div>
      <div style="flex:1;overflow:hidden">
        <div style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.rule.name)}</div>
        <div style="color:var(--grey-400);font-size:10px">${(r.overallScore * 100).toFixed(0)}% correlation${r.exploitableBy.length ? ` · ${r.exploitableBy[0].name}` : ''}</div>
      </div>
    </div>`).join('');
}

function buildNodeDetail(node) {
  const typeColors = { rule: '#603494', technique: '#1565c0', apt: '#c62828', cve: '#e65100' };
  const color = typeColors[node.type] ?? '#666';
  return `
    <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:${color};margin-bottom:4px">${node.type}</div>
    <div style="font-weight:700;font-size:0.9rem;margin-bottom:6px">${esc(node.label ?? node.id)}</div>
    ${node.description ? `<div style="font-size:12px;color:var(--grey-600);line-height:1.5">${esc(node.description.slice(0, 150))}</div>` : ''}
    ${node.correlationScore != null ? `<div style="margin-top:8px;font-size:12px"><span style="font-weight:700;color:${color}">${(node.correlationScore * 100).toFixed(0)}%</span> correlation score</div>` : ''}
    ${node.cvss ? `<div style="font-size:12px;margin-top:4px">CVSS: <span style="font-weight:700;color:#e65100">${node.cvss}</span></div>` : ''}`;
}

function exportReport() {
  if (!state.corrResults) return;
  const report = generateReport(state.corrResults, state.corrMode);
  downloadFile(JSON.stringify(report, null, 2), `dxc-correlation-report-${Date.now()}.json`, 'application/json');
  showToast('Correlation report exported', 'success');
}

/* ── EXAMPLES SECTION ───────────────────── */
let examplesInitialized = false;

function initExamples() {
  if (examplesInitialized) return;
  examplesInitialized = true;
  // Download buttons are wired via onclick in HTML
}

/* ── Modal helpers ──────────────────────── */
function setupModals() {
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', e => {
      if (e.target === overlay) overlay.classList.remove('open');
    });
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
    }
  });
}

window.closeModal = id => document.getElementById(id)?.classList.remove('open');

/* ── File reader helper ─────────────────── */
function readFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = e => resolve(e.target.result);
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}

/* ── Example download helpers ───────────── */
window.downloadExample = function(filename) {
  const a = document.createElement('a');
  a.href = `examples/${filename}`;
  a.download = filename;
  a.click();
  showToast(`Downloading ${filename}…`, 'success');
};

window.useExampleForCorrelation = function(filename) {
  navigateTo('correlation');
  showToast(`💡 Upload ${filename} in the Correlation section`, 'info', 5000);
};

window.useExampleForComparison = function(filename) {
  navigateTo('rules');
  showToast(`💡 Upload ${filename} in the Rules Comparator tab`, 'info', 5000);
};
