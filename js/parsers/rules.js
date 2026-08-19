/* ============================================================
   SOC/SIEM Rule Parser
   Supports: Sigma (YAML), Elastic EQL (JSON), Splunk (JSON),
             Suricata (YAML), Generic JSON/YAML
   ============================================================ */

/**
 * Parse a file's content into a normalized rules array
 * @param {string} content  - raw file text
 * @param {string} filename - used to guess format
 * @returns {{ format: string, rules: NormalizedRule[], raw: string, error: string|null }}
 */
export function parseRuleFile(content, filename = '') {
  const ext  = filename.toLowerCase().split('.').pop();
  const lower = content.slice(0, 500).toLowerCase();

  try {
    // Try JSON first
    if (ext === 'json' || (ext !== 'yaml' && ext !== 'yml' && content.trimStart().startsWith('{'))) {
      return parseJson(content, filename);
    }
    // YAML
    if (ext === 'yaml' || ext === 'yml') {
      return parseYaml(content, filename);
    }
    // Fallback: try JSON, then YAML
    try { return parseJson(content, filename); }
    catch { return parseYaml(content, filename); }
  } catch (err) {
    return { format: 'unknown', rules: [], raw: content, error: err.message };
  }
}

/* ── JSON Parsers ─────────────────────────── */
function parseJson(content, filename) {
  const obj = JSON.parse(content);
  const lower = filename.toLowerCase();

  // Elastic SIEM (has "rules" array with eql language)
  if (obj.rules && Array.isArray(obj.rules)) {
    if (obj.rules[0]?.language === 'eql' || obj.metadata?.framework?.toLowerCase().includes('elastic')) {
      return { format: 'Elastic SIEM', rules: obj.rules.map(normalizeElastic), raw: content, error: null };
    }
    // Splunk (has correlation_searches)
    if (obj.correlation_searches) {
      return { format: 'Splunk ES', rules: obj.correlation_searches.map(normalizeSplunk), raw: content, error: null };
    }
    // Generic JSON array
    return { format: 'Generic JSON', rules: obj.rules.map(normalizeGeneric), raw: content, error: null };
  }

  if (obj.correlation_searches && Array.isArray(obj.correlation_searches)) {
    return { format: 'Splunk ES', rules: obj.correlation_searches.map(normalizeSplunk), raw: content, error: null };
  }

  // Single rule object
  if (obj.name || obj.title || obj.rule_id) {
    return { format: 'Generic JSON', rules: [normalizeGeneric(obj)], raw: content, error: null };
  }

  throw new Error('Unrecognized JSON rule format');
}

/* ── YAML Parsers ─────────────────────────── */
function parseYaml(content, filename) {
  if (typeof window.jsyaml === 'undefined') {
    throw new Error('YAML parser not loaded. Please check internet connection.');
  }
  const docs = [];
  // Split multi-document YAML (Sigma files often have --- separators)
  const parts = content.split(/^---\s*$/m).filter(p => p.trim());

  for (const part of parts) {
    try {
      const doc = window.jsyaml.load(part);
      if (doc && typeof doc === 'object') docs.push(doc);
    } catch {}
  }

  if (!docs.length) throw new Error('No valid YAML documents found');

  // Check for metadata-only first document
  const hasMeta = docs[0]?.metadata != null;
  const ruleDocs = hasMeta ? docs.slice(1) : docs;

  // Suricata YAML
  if (docs[0]?.rules && Array.isArray(docs[0].rules)) {
    return { format: 'Suricata NIDS', rules: docs[0].rules.map(normalizeSuricata), raw: content, error: null };
  }
  if (docs[0]?.metadata?.framework?.toLowerCase().includes('suricata') ||
      filename.toLowerCase().includes('suricata') ||
      ruleDocs[0]?.sid != null) {
    const allRules = docs.flatMap(d => d.rules ? d.rules : [d]);
    return { format: 'Suricata NIDS', rules: allRules.map(normalizeSuricata), raw: content, error: null };
  }

  // Sigma (has logsource + detection fields)
  if (ruleDocs.some(d => d.logsource || d.detection || d.title)) {
    return { format: 'Sigma', rules: ruleDocs.map(normalizeSigma), raw: content, error: null };
  }

  return { format: 'Generic YAML', rules: ruleDocs.map(normalizeGeneric), raw: content, error: null };
}

/* ── Normalizers ─────────────────────────── */

/**
 * @typedef {Object} NormalizedRule
 * @property {string} id
 * @property {string} name
 * @property {string} description
 * @property {string} severity        critical|high|medium|low|info
 * @property {string} status
 * @property {string} format          Sigma|Elastic SIEM|Splunk ES|Suricata NIDS|Generic
 * @property {string[]} tactics
 * @property {string[]} techniques    T1234 format
 * @property {string[]} tags
 * @property {string[]} cves
 * @property {string|null} query      detection logic as string
 * @property {Object} raw             original parsed object
 * @property {number} riskScore       0-100
 * @property {string} platform
 */

function normalizeSigma(r) {
  if (!r || typeof r !== 'object') return null;
  const tags = r.tags ?? [];
  const techniques = tags.filter(t => /^attack\.t\d{4}/i.test(t))
    .map(t => t.replace('attack.', '').toUpperCase().replace('_', '.'));
  const tactics = tags.filter(t => /^attack\.[a-z_]+$/.test(t) && !/^attack\.t\d/.test(t))
    .map(t => t.replace('attack.', '').replace(/_/g, ' '));

  const detStr = r.detection
    ? JSON.stringify(r.detection, null, 2)
    : (r.condition ?? '');

  const sev = (r.level ?? r.severity ?? 'medium').toLowerCase();

  return {
    id:          r.id ?? `sigma-${Math.random().toString(36).slice(2, 8)}`,
    name:        r.title ?? r.name ?? 'Untitled Rule',
    description: r.description ?? '',
    severity:    normalizeSeverity(sev),
    status:      r.status ?? 'unknown',
    format:      'Sigma',
    tactics,
    techniques:  extractTechIds(r.mitre?.technique ? [r.mitre.technique] : techniques),
    tags:        tags.filter(t => !t.startsWith('attack.')),
    cves:        extractCves(JSON.stringify(r)),
    query:       detStr,
    platform:    r.logsource?.product ?? r.logsource?.category ?? 'unknown',
    riskScore:   severityToRisk(sev),
    raw:         r,
    falsePositives: Array.isArray(r.falsepositives) ? r.falsepositives : [],
  };
}

function normalizeElastic(r) {
  const sev = (r.severity ?? 'medium').toLowerCase();
  return {
    id:          r.rule_id ?? `elastic-${Math.random().toString(36).slice(2, 8)}`,
    name:        r.name ?? 'Untitled Rule',
    description: r.description ?? '',
    severity:    normalizeSeverity(sev),
    status:      r.enabled ? 'enabled' : 'disabled',
    format:      'Elastic SIEM',
    tactics:     r.mitre?.tactics ?? [],
    techniques:  extractTechIds(r.mitre?.techniques ?? []),
    tags:        r.tags ?? [],
    cves:        extractCves(JSON.stringify(r)),
    query:       r.query ?? '',
    platform:    'Elastic/Endpoint',
    riskScore:   r.risk_score ?? severityToRisk(sev),
    raw:         r,
    falsePositives: Array.isArray(r.false_positives) ? r.false_positives : [],
  };
}

function normalizeSplunk(r) {
  const sev = (r.severity ?? 'medium').toLowerCase();
  return {
    id:          r.name?.replace(/\s+/g, '-').toLowerCase() ?? `splunk-${Math.random().toString(36).slice(2, 8)}`,
    name:        r.name ?? 'Untitled Rule',
    description: r.description ?? '',
    severity:    normalizeSeverity(sev),
    status:      r.status ?? 'enabled',
    format:      'Splunk ES',
    tactics:     r.mitre?.tactics ?? [],
    techniques:  extractTechIds(r.mitre?.techniques ?? []),
    tags:        r.tags ?? [],
    cves:        extractCves(JSON.stringify(r)),
    query:       r.search ?? '',
    platform:    'Splunk',
    riskScore:   r.risk_score ?? severityToRisk(sev),
    raw:         r,
    falsePositives: [],
  };
}

function normalizeSuricata(r) {
  if (!r || typeof r !== 'object') return null;
  const sev = (r.severity ?? r.classtype ?? 'medium').toLowerCase();
  const techIds = extractTechIds([
    ...(r.mitre?.techniques ?? []),
    ...(r.tags ?? []).filter(t => /T\d{4}/i.test(t)).map(t => t.match(/T\d{4}(\.\d{3})?/i)?.[0] ?? '')
  ]);

  return {
    id:          String(r.sid ?? `suricata-${Math.random().toString(36).slice(2, 8)}`),
    name:        r.name ?? r.msg ?? 'Untitled Rule',
    description: r.msg ?? r.name ?? '',
    severity:    normalizeSeverity(sev),
    status:      r.action === 'alert' ? 'enabled' : (r.action ?? 'enabled'),
    format:      'Suricata NIDS',
    tactics:     r.mitre?.tactics ?? [],
    techniques:  techIds,
    tags:        r.tags ?? [],
    cves:        extractCves(JSON.stringify(r)),
    query:       buildSuricataQuery(r),
    platform:    'Network/Suricata',
    riskScore:   severityToRisk(sev),
    raw:         r,
    falsePositives: [],
  };
}

function normalizeGeneric(r) {
  if (!r || typeof r !== 'object') return null;
  const sev = (r.severity ?? r.level ?? r.risk_level ?? 'medium').toLowerCase();
  return {
    id:          r.id ?? r.rule_id ?? `rule-${Math.random().toString(36).slice(2, 8)}`,
    name:        r.name ?? r.title ?? r.rule_name ?? 'Untitled Rule',
    description: r.description ?? r.desc ?? '',
    severity:    normalizeSeverity(sev),
    status:      r.status ?? r.enabled ?? 'unknown',
    format:      'Generic',
    tactics:     r.tactics ?? r.mitre?.tactics ?? [],
    techniques:  extractTechIds(r.techniques ?? r.mitre?.techniques ?? []),
    tags:        r.tags ?? [],
    cves:        extractCves(JSON.stringify(r)),
    query:       r.query ?? r.search ?? r.detection ?? '',
    platform:    r.platform ?? r.product ?? 'unknown',
    riskScore:   severityToRisk(sev),
    raw:         r,
    falsePositives: [],
  };
}

/* ── Helpers ─────────────────────────────── */
function normalizeSeverity(s) {
  if (!s) return 'medium';
  const l = s.toLowerCase();
  if (l.includes('crit')) return 'critical';
  if (l.includes('high') || l.includes('major')) return 'high';
  if (l.includes('med')  || l.includes('warn')) return 'medium';
  if (l.includes('low')  || l.includes('info') || l.includes('minor')) return 'low';
  return 'medium';
}

function severityToRisk(s) {
  const map = { critical: 90, high: 70, major: 70, medium: 50, low: 25, info: 10, minor: 10 };
  return map[s?.toLowerCase()] ?? 50;
}

function extractTechIds(arr) {
  const pattern = /T\d{4}(\.\d{3})?/gi;
  const ids = new Set();
  for (const item of arr) {
    const matches = String(item).match(pattern) ?? [];
    for (const m of matches) ids.add(m.toUpperCase());
  }
  return [...ids];
}

function extractCves(text) {
  const matches = text.match(/CVE-\d{4}-\d{4,7}/gi) ?? [];
  return [...new Set(matches.map(c => c.toUpperCase()))];
}

function buildSuricataQuery(r) {
  const parts = [];
  if (r.protocol) parts.push(`protocol: ${r.protocol}`);
  if (r.src?.ip)  parts.push(`src: ${r.src.ip}:${r.src.port ?? 'any'}`);
  if (r.dst?.ip)  parts.push(`dst: ${r.dst.ip}:${r.dst.port ?? 'any'}`);
  if (r.content_matches) {
    for (const c of r.content_matches) {
      parts.push(`content: "${c.content}"`);
    }
  }
  if (r.pcre) parts.push(`pcre: ${r.pcre}`);
  return parts.join('\n') || (r.msg ?? '');
}

/**
 * Compare two sets of rules and return diff analysis
 */
export function compareRuleSets(rulesA, rulesB, labelA = 'File A', labelB = 'File B') {
  const nameMapA = new Map(rulesA.map(r => [r.name.toLowerCase().trim(), r]));
  const nameMapB = new Map(rulesB.map(r => [r.name.toLowerCase().trim(), r]));

  const common = [];
  const onlyA  = [];
  const onlyB  = [];
  const modified = [];

  for (const [name, ruleA] of nameMapA) {
    if (nameMapB.has(name)) {
      const ruleB = nameMapB.get(name);
      // Check if they're meaningfully different
      if (ruleA.severity !== ruleB.severity ||
          ruleA.query?.trim() !== ruleB.query?.trim()) {
        modified.push({ ruleA, ruleB, name });
      } else {
        common.push({ ruleA, ruleB, name });
      }
    } else {
      onlyA.push(ruleA);
    }
  }

  for (const [name, ruleB] of nameMapB) {
    if (!nameMapA.has(name)) {
      onlyB.push(ruleB);
    }
  }

  // Technique overlap
  const techA = new Set(rulesA.flatMap(r => r.techniques));
  const techB = new Set(rulesB.flatMap(r => r.techniques));
  const techCommon = [...techA].filter(t => techB.has(t));
  const techOnlyA  = [...techA].filter(t => !techB.has(t));
  const techOnlyB  = [...techB].filter(t => !techA.has(t));

  return {
    labelA, labelB,
    common,
    onlyA,
    onlyB,
    modified,
    techniques: { common: techCommon, onlyA: techOnlyA, onlyB: techOnlyB },
    stats: {
      totalA: rulesA.length,
      totalB: rulesB.length,
      commonCount:   common.length,
      onlyACount:    onlyA.length,
      onlyBCount:    onlyB.length,
      modifiedCount: modified.length,
      overlapPct:    rulesA.length ?
        Math.round((common.length / Math.max(rulesA.length, rulesB.length)) * 100) : 0,
    },
  };
}
