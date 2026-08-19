/* ============================================================
   MITRE ATT&CK STIX Data Client
   Fetches Enterprise ATT&CK v15 from GitHub STIX bundle
   ============================================================ */
import { sessionGet, sessionSet } from '../utils/helpers.js';

const ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
const CACHE_KEY  = 'mitre:attack:enterprise';

let _attackData = null;
let _loading    = null;

/**
 * Load and cache MITRE ATT&CK STIX bundle
 */
export async function loadAttackData() {
  if (_attackData) return _attackData;
  if (_loading)    return _loading;

  // Try session storage first
  const cached = sessionGet(CACHE_KEY);
  if (cached) {
    _attackData = cached;
    return cached;
  }

  _loading = (async () => {
    const res = await fetch(ATTACK_URL);
    if (!res.ok) throw new Error(`Failed to load ATT&CK data: ${res.status}`);
    const bundle = await res.json();
    _attackData = processBundle(bundle);
    sessionSet(CACHE_KEY, _attackData);
    _loading = null;
    return _attackData;
  })();
  return _loading;
}

/**
 * Process raw STIX bundle into indexed maps
 */
function processBundle(bundle) {
  const objects = bundle.objects ?? [];
  const byId    = new Map();
  const byType  = {};

  for (const obj of objects) {
    if (!obj.id) continue;
    byId.set(obj.id, obj);
    if (!byType[obj.type]) byType[obj.type] = [];
    byType[obj.type].push(obj);
  }

  // Index techniques by external ID (T1234)
  const techniqueMap = new Map();
  for (const t of (byType['attack-pattern'] ?? [])) {
    const extId = getExtId(t);
    if (extId) techniqueMap.set(extId, t);
  }

  // Index groups
  const groupMap = new Map();
  for (const g of (byType['intrusion-set'] ?? [])) {
    const extId = getExtId(g);
    if (extId) groupMap.set(extId, g);
  }

  // Build group → techniques mapping via 'uses' relationships
  const groupTechniques = new Map(); // group STIX id → Set<technique STIX id>
  for (const rel of (byType['relationship'] ?? [])) {
    if (rel.relationship_type === 'uses' &&
        rel.source_ref?.startsWith('intrusion-set--') &&
        rel.target_ref?.startsWith('attack-pattern--')) {
      if (!groupTechniques.has(rel.source_ref)) {
        groupTechniques.set(rel.source_ref, new Set());
      }
      groupTechniques.get(rel.source_ref).add(rel.target_ref);
    }
  }

  // Build tactic map
  const tacticMap = new Map();
  for (const tactic of (byType['x-mitre-tactic'] ?? [])) {
    const extId = getExtId(tactic);
    if (extId) tacticMap.set(extId, tactic.name);
    const shortName = tactic.x_mitre_shortname;
    if (shortName) tacticMap.set(shortName, tactic.name);
  }

  return {
    objects,
    byId,
    byType,
    techniqueMap,
    groupMap,
    groupTechniques,
    tacticMap,
  };
}

function getExtId(obj) {
  return obj?.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id ?? null;
}

function getUrl(obj) {
  return obj?.external_references?.find(r => r.source_name === 'mitre-attack')?.url ?? null;
}

/**
 * Get all APT groups (intrusion sets), parsed into a simplified format
 */
export function getGroups(data) {
  return (data.byType['intrusion-set'] ?? [])
    .filter(g => !g.revoked && !g.x_mitre_deprecated)
    .map(g => {
      const extId    = getExtId(g);
      const aliases  = g.aliases ?? [];
      const stixId   = g.id;
      const techIds  = data.groupTechniques.get(stixId) ?? new Set();
      const techniques = [...techIds]
        .map(tid => data.byId.get(tid))
        .filter(Boolean)
        .filter(t => !t.revoked && !t.x_mitre_deprecated)
        .map(t => parseTechnique(t, data));
      return {
        id:          extId,
        stixId,
        name:        g.name,
        aliases:     aliases.filter(a => a !== g.name),
        description: g.description ?? '',
        url:         getUrl(g),
        techniques,
        techniqueCount: techniques.length,
        // Attribution metadata if available
        country:     g.x_mitre_contributors?.join(', ') ?? null,
      };
    })
    .filter(g => g.id)
    .sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Parse a STIX technique into a clean object
 */
export function parseTechnique(t, data) {
  if (!t) return null;
  const extId  = getExtId(t);
  const phases = t.kill_chain_phases ?? [];
  const tactics = phases
    .filter(p => p.kill_chain_name === 'mitre-attack')
    .map(p => data.tacticMap.get(p.phase_name) ?? p.phase_name);

  const platforms    = t.x_mitre_platforms ?? [];
  const dataSources  = t.x_mitre_data_sources ?? [];
  const detection    = t.x_mitre_detection ?? '';
  const isSubTech    = extId?.includes('.') ?? false;

  return {
    id:          extId,
    stixId:      t.id,
    name:        t.name,
    description: t.description ?? '',
    tactics,
    platforms,
    dataSources,
    detection,
    url:         getUrl(t),
    isSubTechnique: isSubTech,
    parentId:    isSubTech ? extId?.split('.')[0] : null,
  };
}

/**
 * Get a single technique by ID (e.g. "T1059.001")
 */
export function getTechniqueById(data, id) {
  const stixObj = data.techniqueMap.get(id);
  return stixObj ? parseTechnique(stixObj, data) : null;
}

/**
 * Get all unique tactics
 */
export function getAllTactics(data) {
  const tactics = new Set();
  for (const t of (data.byType['attack-pattern'] ?? [])) {
    const phases = t.kill_chain_phases ?? [];
    for (const p of phases) {
      if (p.kill_chain_name === 'mitre-attack') {
        tactics.add(data.tacticMap.get(p.phase_name) ?? p.phase_name);
      }
    }
  }
  return [...tactics].sort();
}

/**
 * Get software/malware/tools associated with a technique
 */
export function getSoftwareForTechnique(data, techniqueStixId) {
  const software = [];
  for (const rel of (data.byType['relationship'] ?? [])) {
    if (rel.relationship_type === 'uses' &&
        (rel.source_ref?.startsWith('malware--') || rel.source_ref?.startsWith('tool--')) &&
        rel.target_ref === techniqueStixId) {
      const sw = data.byId.get(rel.source_ref);
      if (sw) software.push({ name: sw.name, type: sw.type });
    }
  }
  return software;
}

/**
 * Get mitigations for a technique
 */
export function getMitigationsForTechnique(data, techniqueStixId) {
  const mitigations = [];
  for (const rel of (data.byType['relationship'] ?? [])) {
    if (rel.relationship_type === 'mitigates' &&
        rel.source_ref?.startsWith('course-of-action--') &&
        rel.target_ref === techniqueStixId) {
      const m = data.byId.get(rel.source_ref);
      if (m) mitigations.push({ name: m.name, description: m.description ?? '' });
    }
  }
  return mitigations;
}
