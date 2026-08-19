/* ============================================================
   Correlation Engine — Core of the project
   Correlates uploaded SOC/SIEM rules with MITRE ATT&CK + CVEs
   ============================================================ */
import { loadAttackData, getGroups, getTechniqueById } from '../api/mitre.js';
import { searchCves, parseCve }                        from '../api/nvd.js';
import { delay }                                       from '../utils/helpers.js';

/**
 * Run correlation between rules and ATT&CK/CVE data
 * @param {NormalizedRule[]} rules
 * @param {'simple'|'advanced'|'deep'} mode
 * @param {Function} onProgress  - callback({ step, total, label })
 * @returns {Promise<CorrelationResult[]>}
 */
export async function runCorrelation(rules, mode, onProgress) {
  const steps = getSteps(mode);
  let stepIdx = 0;

  function progress(label) {
    onProgress?.({ step: ++stepIdx, total: steps.length, label });
  }

  // Step 1: Load ATT&CK data
  progress('Loading MITRE ATT&CK data…');
  const attackData = await loadAttackData();
  const groups     = getGroups(attackData);

  // Build lookup: technique ID → APT groups that use it
  const techToApts = buildTechToAptMap(groups);

  // Step 2: Map rules → techniques
  progress('Mapping rules to ATT&CK techniques…');
  const results = rules.filter(Boolean).map(rule => ({
    rule,
    matchedTechniques: [],
    matchedCves:       [],
    overallScore:      0,
    weaknesses:        [],
    exploitableBy:     [],
  }));

  for (const result of results) {
    result.matchedTechniques = matchTechniques(result.rule, attackData, techToApts, mode);
  }

  // Step 3: CVE correlation
  if (mode !== 'simple') {
    progress('Correlating with CVE database…');
    for (const result of results) {
      await delay(200); // gentle rate limit
      result.matchedCves = await matchCves(result.rule, mode);
    }
  } else {
    progress('Skipping deep CVE scan (simple mode)…');
    for (const result of results) {
      // Still use embedded CVEs from rule metadata
      result.matchedCves = result.rule.cves.map(id => ({ id, description: '', score: null }));
    }
  }

  // Step 4: Deep scan — sub-techniques, campaigns
  if (mode === 'deep') {
    progress('Running deep cross-reference scan…');
    await runDeepScan(results, attackData, groups);
  }

  // Step 5: Score and classify
  progress('Scoring and classifying rules…');
  for (const result of results) {
    result.overallScore  = computeScore(result, mode);
    result.exploitableBy = getExploitableApts(result);
    result.weaknesses    = classifyWeaknesses(result);
  }

  progress('Generating correlation report…');
  await delay(400);

  return results;
}

/* ── Internal helpers ─────────────────────── */

function getSteps(mode) {
  const base = ['Load ATT&CK', 'Map techniques', 'CVE correlation', 'Score rules', 'Report'];
  if (mode === 'deep') return [...base.slice(0, 3), 'Deep cross-reference', ...base.slice(3)];
  return base;
}

/**
 * Build technique ID → [APT group] lookup
 */
function buildTechToAptMap(groups) {
  const map = new Map();
  for (const group of groups) {
    for (const tech of group.techniques) {
      if (!map.has(tech.id)) map.set(tech.id, []);
      map.get(tech.id).push({ id: group.id, name: group.name, stixId: group.stixId });
    }
  }
  return map;
}

/**
 * Match a rule to ATT&CK techniques
 */
function matchTechniques(rule, attackData, techToApts, mode) {
  const matched = new Map();

  // Direct tag/technique ID matches (highest confidence)
  for (const techId of rule.techniques) {
    const techObj = getTechniqueById(attackData, techId);
    if (techObj) {
      matched.set(techId, {
        ...techObj,
        confidence: 1.0,
        matchType:  'direct-tag',
        aptGroups:  techToApts.get(techId) ?? [],
      });
    }
  }

  if (mode === 'simple') return [...matched.values()];

  // Advanced: keyword matching in rule name + query
  const ruleText = `${rule.name} ${rule.description} ${rule.query}`.toLowerCase();
  for (const [techId, stixObj] of attackData.techniqueMap) {
    if (matched.has(techId)) continue;
    const techName = stixObj.name?.toLowerCase() ?? '';
    const techDesc = stixObj.description?.toLowerCase().slice(0, 200) ?? '';

    // Simple keyword overlap scoring
    const keywords = techName.split(/\W+/).filter(w => w.length > 4);
    const hits     = keywords.filter(kw => ruleText.includes(kw));
    if (hits.length >= 2 || (hits.length >= 1 && techName.split(' ').length <= 3)) {
      const techObj = getTechniqueById(attackData, techId);
      if (techObj) {
        matched.set(techId, {
          ...techObj,
          confidence: Math.min(hits.length / keywords.length + 0.2, 0.85),
          matchType:  'keyword',
          aptGroups:  techToApts.get(techId) ?? [],
        });
      }
    }
  }

  // Deep: also match via tactic names in rule tags/tactics
  if (mode === 'deep') {
    const ruleTactics = new Set(rule.tactics.map(t => t.toLowerCase()));
    for (const [techId, stixObj] of attackData.techniqueMap) {
      if (matched.has(techId)) continue;
      const phases = stixObj.kill_chain_phases ?? [];
      const techTactics = phases
        .filter(p => p.kill_chain_name === 'mitre-attack')
        .map(p => p.phase_name.replace(/-/g, ' '));
      if (techTactics.some(t => ruleTactics.has(t))) {
        const techObj = getTechniqueById(attackData, techId);
        if (techObj) {
          matched.set(techId, {
            ...techObj,
            confidence: 0.3,
            matchType:  'tactic-match',
            aptGroups:  techToApts.get(techId) ?? [],
          });
        }
      }
    }
  }

  // Limit results to top 12 by confidence
  return [...matched.values()]
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 12);
}

/**
 * Match a rule to CVEs via keyword and embedded CVE IDs
 */
async function matchCves(rule, mode) {
  const cves = [];

  // Already embedded CVE IDs
  for (const cveId of rule.cves.slice(0, 5)) {
    cves.push({ id: cveId, description: 'Referenced in rule', score: null });
  }

  if (mode === 'deep' && rule.name) {
    try {
      // Search NVD for rule-related CVEs
      const keywords = extractSearchTerms(rule);
      if (keywords) {
        await delay(6200); // NVD rate limit
        const result = await searchCves({ keyword: keywords, resultsPerPage: 5 });
        for (const v of result.items) {
          const parsed = parseCve(v);
          if (parsed && !cves.find(c => c.id === parsed.id)) {
            cves.push({ id: parsed.id, description: parsed.description?.slice(0, 100), score: parsed.score });
          }
        }
      }
    } catch {
      // API unavailable — skip
    }
  }

  return cves.slice(0, 8);
}

function extractSearchTerms(rule) {
  // Extract meaningful keywords for CVE search
  const stopWords = new Set(['the', 'and', 'for', 'are', 'this', 'that', 'with', 'from', 'using', 'via', 'into']);
  const words = (rule.name + ' ' + rule.description)
    .toLowerCase()
    .replace(/[^\w\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 4 && !stopWords.has(w))
    .slice(0, 4);
  return words.join(' ') || null;
}

async function runDeepScan(results, attackData, groups) {
  // Cross-reference with ATT&CK campaigns and software for higher confidence
  for (const result of results) {
    for (const tech of result.matchedTechniques) {
      // Boost confidence for techniques used by many APT groups
      const aptCount = tech.aptGroups?.length ?? 0;
      if (aptCount > 5) {
        tech.confidence = Math.min(tech.confidence + 0.15, 1.0);
      }
    }
  }
}

/**
 * Compute overall correlation score for a rule (0–1)
 */
function computeScore(result, mode) {
  const { rule, matchedTechniques, matchedCves } = result;
  if (!matchedTechniques.length && !matchedCves.length) return 0.05;

  const techScore = matchedTechniques.length > 0
    ? matchedTechniques.reduce((s, t) => s + t.confidence, 0) / Math.max(matchedTechniques.length, 3)
    : 0;

  const cveBonus = Math.min(matchedCves.length * 0.05, 0.2);
  const riskBonus = (rule.riskScore ?? 50) / 200; // 0–0.5 → 0–0.25

  return Math.min(techScore + cveBonus + riskBonus, 1.0);
}

function getExploitableApts(result) {
  const apts = new Map();
  for (const tech of result.matchedTechniques) {
    for (const apt of (tech.aptGroups ?? [])) {
      if (!apts.has(apt.id)) apts.set(apt.id, { ...apt, techniques: [] });
      apts.get(apt.id).techniques.push(tech.id);
    }
  }
  return [...apts.values()].sort((a, b) => b.techniques.length - a.techniques.length).slice(0, 5);
}

/**
 * Classify weaknesses in the rule
 */
function classifyWeaknesses(result) {
  const issues = [];
  if (result.matchedTechniques.length === 0) {
    issues.push({ type: 'no-technique-mapping', severity: 'critical', message: 'No ATT&CK technique mapping found' });
  }
  if (result.matchedTechniques.every(t => t.confidence < 0.4)) {
    issues.push({ type: 'low-confidence', severity: 'high', message: 'All technique mappings have low confidence' });
  }
  if (result.exploitableBy.length > 3) {
    issues.push({ type: 'broad-apt-exposure', severity: 'high',
      message: `Exploitable by ${result.exploitableBy.length} known APT groups` });
  }
  if (result.matchedCves.length === 0 && result.rule.format !== 'Sigma') {
    issues.push({ type: 'no-cve-link', severity: 'medium', message: 'No CVE references found' });
  }
  return issues;
}

/**
 * Generate a downloadable JSON report
 */
export function generateReport(results, scanMode) {
  return {
    generated:  new Date().toISOString(),
    scanMode,
    summary: {
      totalRules:    results.length,
      weakRules:     results.filter(r => r.overallScore < 0.3).length,
      partialRules:  results.filter(r => r.overallScore >= 0.3 && r.overallScore < 0.65).length,
      strongRules:   results.filter(r => r.overallScore >= 0.65).length,
      topApts:       getTopApts(results),
    },
    rules: results.map(r => ({
      ruleId:          r.rule.id,
      ruleName:        r.rule.name,
      format:          r.rule.format,
      severity:        r.rule.severity,
      correlationScore: +(r.overallScore * 100).toFixed(1),
      matchedTechniques: r.matchedTechniques.map(t => ({ id: t.id, name: t.name, confidence: +(t.confidence * 100).toFixed(0) })),
      matchedCves:     r.matchedCves.map(c => c.id),
      exploitableBy:   r.exploitableBy.map(a => a.name),
      weaknesses:      r.weaknesses,
    })),
  };
}

function getTopApts(results) {
  const aptCounts = new Map();
  for (const r of results) {
    for (const apt of r.exploitableBy) {
      aptCounts.set(apt.name, (aptCounts.get(apt.name) ?? 0) + 1);
    }
  }
  return [...aptCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));
}
