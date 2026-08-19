/* ============================================================
   NVD CVE API Client
   Uses api.nvd.nist.gov/vulnerabilities/2.0 (public, free)
   Includes robust live API querying, client-side filtering, and
   notable fallback vulnerabilities.
   ============================================================ */
import { sessionGet, sessionSet, delay } from '../utils/helpers.js';

const BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RATE_LIMIT_MS = 6100; // 5 req per 30s = 6s between calls (no key)
let lastCall = 0;

async function rateLimitedFetch(url) {
  const now = Date.now();
  const wait = Math.max(0, RATE_LIMIT_MS - (now - lastCall));
  if (wait > 0) await delay(wait);
  lastCall = Date.now();
  const res = await fetch(url);
  if (!res.ok) {
    if (res.status === 403) throw new Error('NVD API rate limit reached. Please wait 30 seconds.');
    throw new Error(`NVD API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/**
 * Curated list of notable, real-world CVEs as fallback / baseline
 */
export const NOTABLE_CVES = [
  {
    id: 'CVE-2021-44228',
    published: '2021-12-10T10:15:00.000',
    lastModified: '2024-01-15T12:00:00.000',
    description: 'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints (Log4Shell).',
    score: 10.0,
    severity: 'critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    cwes: ['CWE-502', 'CWE-400', 'CWE-20'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228', tags: ['NVD'] },
      { url: 'https://logging.apache.org/log4j/2.x/security.html', tags: ['Vendor Advisory'] }
    ],
    cpes: ['cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  },
  {
    id: 'CVE-2021-34473',
    published: '2021-07-13T23:15:00.000',
    lastModified: '2023-11-01T14:20:00.000',
    description: 'Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyShell). Enables unauthenticated attackers to execute arbitrary code on vulnerable Exchange servers.',
    score: 9.8,
    severity: 'critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwes: ['CWE-287', 'CWE-918'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-34473', tags: ['NVD'] },
      { url: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473', tags: ['Vendor Advisory'] }
    ],
    cpes: ['cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_9:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  },
  {
    id: 'CVE-2020-0796',
    published: '2020-03-12T18:15:00.000',
    lastModified: '2023-08-10T11:00:00.000',
    description: 'Windows SMBv3 Compression Remote Code Execution Vulnerability (SMBGhost / Coronablue). A remote code execution vulnerability exists in the way Microsoft Server Message Block 3.1.1 handles certain requests.',
    score: 10.0,
    severity: 'critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    cwes: ['CWE-119', 'CWE-190'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-0796', tags: ['NVD'] }
    ],
    cpes: ['cpe:2.3:o:microsoft:windows_10:1903:*:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  },
  {
    id: 'CVE-2022-22965',
    published: '2022-04-01T18:15:00.000',
    lastModified: '2023-12-05T16:00:00.000',
    description: 'Spring Framework Remote Code Execution Vulnerability (Spring4Shell). A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding.',
    score: 9.8,
    severity: 'critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwes: ['CWE-94', 'CWE-502'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965', tags: ['NVD'] }
    ],
    cpes: ['cpe:2.3:a:vmware:spring_framework:5.3.17:*:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  },
  {
    id: 'CVE-2022-30190',
    published: '2022-05-31T21:15:00.000',
    lastModified: '2023-09-12T10:00:00.000',
    description: 'Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability (Follina). Allows execution of arbitrary code when MSDT is called using the URL protocol from an calling application such as Word.',
    score: 7.8,
    severity: 'high',
    vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
    cwes: ['CWE-78', 'CWE-20'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-30190', tags: ['NVD'] }
    ],
    cpes: ['cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  },
  {
    id: 'CVE-2023-34362',
    published: '2023-06-02T13:15:00.000',
    lastModified: '2024-02-01T15:00:00.000',
    description: 'MOVEit Transfer SQL Injection Vulnerability. In MOVEit Transfer before 2021.0.6, 2021.1.4, 2022.0.4, 2022.1.5, 2023.0.1, an unauthenticated attacker could gain access to MOVEit Transfer database.',
    score: 9.8,
    severity: 'critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwes: ['CWE-89'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-34362', tags: ['NVD'] }
    ],
    cpes: ['cpe:2.3:a:progress:moveit_transfer:2023.0.0:*:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  },
  {
    id: 'CVE-2023-4966',
    published: '2023-10-10T14:15:00.000',
    lastModified: '2024-01-20T12:00:00.000',
    description: 'Citrix NetScaler ADC and Gateway Sensitive Information Disclosure (CitrixBleed). Unauthenticated buffer overflow allows session token disclosure.',
    score: 9.4,
    severity: 'critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    cwes: ['CWE-119', 'CWE-200'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-4966', tags: ['NVD'] }
    ],
    cpes: ['cpe:2.3:a:citrix:netscaler_adc:13.1:*:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  },
  {
    id: 'CVE-2021-34523',
    published: '2021-07-13T23:15:00.000',
    lastModified: '2023-08-01T12:00:00.000',
    description: 'Microsoft Exchange Server Elevation of Privilege Vulnerability (ProxyShell component). Allows an attacker to elevate privileges on Exchange servers.',
    score: 9.0,
    severity: 'critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    cwes: ['CWE-269'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-34523', tags: ['NVD'] }
    ],
    cpes: ['cpe:2.3:a:microsoft:exchange_server:2016:*:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  },
  {
    id: 'CVE-2021-41773',
    published: '2021-10-05T20:15:00.000',
    lastModified: '2023-11-15T09:00:00.000',
    description: 'Apache HTTP Server 2.4.49 Path Traversal and File Disclosure. A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.',
    score: 7.5,
    severity: 'high',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    cwes: ['CWE-22'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773', tags: ['NVD'] }
    ],
    cpes: ['cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  },
  {
    id: 'CVE-2023-24489',
    published: '2023-07-10T16:15:00.000',
    lastModified: '2024-02-10T11:00:00.000',
    description: 'Citrix ShareFile StorageZones Controller Unauthenticated Remote Code Execution / Reflected Cross-Site Scripting (XSS).',
    score: 9.8,
    severity: 'critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwes: ['CWE-79', 'CWE-434'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-24489', tags: ['NVD'] }
    ],
    cpes: ['cpe:2.3:a:citrix:sharefile_storagezones_controller:5.11.23:*:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  },
  {
    id: 'CVE-2023-35078',
    published: '2023-07-24T12:15:00.000',
    lastModified: '2024-01-18T14:00:00.000',
    description: 'Ivanti Endpoint Manager Mobile (EPMM) Authentication Bypass Vulnerability. Allows unauthenticated access to specific API endpoints and SQL queries.',
    score: 9.8,
    severity: 'critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cwes: ['CWE-287', 'CWE-89'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-35078', tags: ['NVD'] }
    ],
    cpes: ['cpe:2.3:a:ivanti:endpoint_manager_mobile:11.10.0.0:*:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  },
  {
    id: 'CVE-2020-1472',
    published: '2020-08-17T19:15:00.000',
    lastModified: '2023-09-01T15:00:00.000',
    description: 'Netlogon Elevation of Privilege Vulnerability (Zerologon). An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller.',
    score: 10.0,
    severity: 'critical',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    cwes: ['CWE-269', 'CWE-330'],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-1472', tags: ['NVD'] }
    ],
    cpes: ['cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*'],
    vulnStatus: 'Analyzed'
  }
];

/**
 * Fetch a single CVE by ID
 */
export async function fetchCveById(cveId) {
  const cleanId = cveId.toUpperCase().trim();
  const cacheKey = `cve:${cleanId}`;
  const cached = sessionGet(cacheKey);
  if (cached) return cached;

  // Check notable list first
  const notableMatch = NOTABLE_CVES.find(c => c.id === cleanId);
  if (notableMatch) {
    const obj = { cve: formatNotableToNvd(notableMatch) };
    sessionSet(cacheKey, obj);
    return obj;
  }

  try {
    const url = `${BASE_URL}?cveId=${encodeURIComponent(cleanId)}`;
    const data = await rateLimitedFetch(url);
    const result = data?.vulnerabilities?.[0] ?? null;
    if (result) sessionSet(cacheKey, result);
    return result;
  } catch (err) {
    console.warn('Live CVE fetch failed:', err);
    return null;
  }
}

function formatNotableToNvd(c) {
  return {
    id: c.id,
    published: c.published,
    lastModified: c.lastModified,
    vulnStatus: c.vulnStatus,
    descriptions: [{ lang: 'en', value: c.description }],
    metrics: {
      cvssMetricV31: [{
        cvssData: {
          baseScore: c.score,
          baseSeverity: c.severity.toUpperCase(),
          vectorString: c.vector
        }
      }]
    },
    weaknesses: c.cwes.map(w => ({ description: [{ lang: 'en', value: w }] })),
    references: c.references.map(r => ({ url: r.url, tags: r.tags })),
    configurations: [{
      nodes: [{
        cpeMatch: c.cpes.map(cp => ({ criteria: cp }))
      }]
    }]
  };
}

/**
 * Search CVEs by keyword + optional filters
 */
export async function searchCves(opts = {}) {
  const params = new URLSearchParams();
  const userKeyword = opts.keyword?.trim();
  const userCwe     = opts.cweId?.trim();

  if (userKeyword) params.set('keywordSearch', userKeyword);
  if (userCwe)     params.set('cweId', userCwe);

  let dateStart = opts.dateStart;
  let dateEnd   = opts.dateEnd;

  if (dateStart || dateEnd) {
    const todayStr = new Date().toISOString().split('T')[0];
    if (!dateStart && dateEnd) {
      const d = new Date(dateEnd);
      d.setDate(d.getDate() - 90);
      dateStart = d.toISOString().split('T')[0];
    } else if (dateStart && !dateEnd) {
      const d = new Date(dateStart);
      d.setDate(d.getDate() + 90);
      const now = new Date();
      dateEnd = d > now ? todayStr : d.toISOString().split('T')[0];
    }
    const startMs = new Date(dateStart).getTime();
    const endMs   = new Date(dateEnd).getTime();
    const diffDays = (endMs - startMs) / (1000 * 60 * 60 * 24);
    if (diffDays > 120) {
      const adjusted = new Date(endMs - (119 * 24 * 60 * 60 * 1000));
      dateStart = adjusted.toISOString().split('T')[0];
    }
    params.set('pubStartDate', dateStart + 'T00:00:00.000');
    params.set('pubEndDate',   dateEnd   + 'T23:59:59.999');
  } else if (!userKeyword && !userCwe) {
    // Default broad search for populated results
    params.set('keywordSearch', 'vulnerability');
  }

  params.set('startIndex', opts.startIndex ?? 0);
  params.set('resultsPerPage', opts.resultsPerPage ?? 40);

  let apiItems = [];
  let totalCount = 0;

  try {
    const cacheKey = `cve-search:${params.toString()}`;
    let rawData = sessionGet(cacheKey);
    if (!rawData) {
      const url = `${BASE_URL}?${params.toString()}`;
      rawData = await rateLimitedFetch(url);
      sessionSet(cacheKey, rawData);
    }
    apiItems = (rawData.vulnerabilities ?? []).map(parseCve).filter(Boolean);
    totalCount = rawData.totalResults ?? apiItems.length;
  } catch (err) {
    console.warn('NVD API fetch warning, fallback to notable list:', err);
  }

  // Merge notable CVEs with live API items
  const cveMap = new Map();
  for (const c of NOTABLE_CVES) cveMap.set(c.id, c);
  for (const c of apiItems)     cveMap.set(c.id, c);

  let items = [...cveMap.values()];

  // Filter by Keyword
  if (userKeyword) {
    const kw = userKeyword.toLowerCase();
    items = items.filter(c =>
      c.id.toLowerCase().includes(kw) ||
      c.description.toLowerCase().includes(kw) ||
      c.cwes.some(w => w.toLowerCase().includes(kw))
    );
  }

  // Filter by CWE
  if (userCwe) {
    items = items.filter(c => c.cwes.some(w => w.toUpperCase().includes(userCwe.toUpperCase())));
  }

  // Filter by CVSS min/max scores
  if (opts.cvssMin != null && opts.cvssMin > 0) {
    items = items.filter(c => c.score != null && c.score >= opts.cvssMin);
  }
  if (opts.cvssMax != null && opts.cvssMax < 10) {
    items = items.filter(c => c.score != null && c.score <= opts.cvssMax);
  }

  // Filter by Date range
  if (opts.dateStart) {
    const sMs = new Date(opts.dateStart).getTime();
    items = items.filter(c => new Date(c.published).getTime() >= sMs);
  }
  if (opts.dateEnd) {
    const eMs = new Date(opts.dateEnd + 'T23:59:59').getTime();
    items = items.filter(c => new Date(c.published).getTime() <= eMs);
  }

  return {
    total: Math.max(totalCount, items.length),
    items,
    startIndex: opts.startIndex ?? 0,
  };
}

export async function fetchRecentCves(count = 40) {
  return searchCves({ keyword: 'CVE-2024', resultsPerPage: count });
}

/**
 * Extract structured info from a CVE vulnerability object
 */
export function parseCve(vuln) {
  if (!vuln?.cve) return null;
  const c = vuln.cve;
  const desc = c.descriptions?.find(d => d.lang === 'en')?.value ?? 'No description available.';
  const cvssV3 = c.metrics?.cvssMetricV31?.[0] ?? c.metrics?.cvssMetricV30?.[0] ?? null;
  const cvssV2 = c.metrics?.cvssMetricV2?.[0] ?? null;
  const score = cvssV3?.cvssData?.baseScore ?? cvssV2?.cvssData?.baseScore ?? null;
  const severity = cvssV3?.cvssData?.baseSeverity ?? cvssV2?.baseSeverity ?? 'UNKNOWN';
  const vector = cvssV3?.cvssData?.vectorString ?? cvssV2?.cvssData?.vectorString ?? null;
  const cwes = c.weaknesses?.flatMap(w => w.description?.map(d => d.value) ?? []) ?? [];
  const refs = (c.references ?? []).slice(0, 8).map(r => ({ url: r.url, tags: r.tags ?? [] }));
  const cpes = c.configurations?.flatMap(cfg =>
    cfg.nodes?.flatMap(n => n.cpeMatch?.map(m => m.criteria) ?? []) ?? []
  ) ?? [];

  return {
    id:           c.id,
    published:    c.published,
    lastModified: c.lastModified,
    description:  desc,
    score,
    severity:     severity.toLowerCase(),
    vector,
    cwes:         [...new Set(cwes)],
    references:   refs,
    cpes:         [...new Set(cpes)].slice(0, 12),
    vulnStatus:   c.vulnStatus ?? 'N/A',
  };
}

/**
 * Common CWE categories for filter dropdown
 */
export const CWE_CATEGORIES = [
  { id: '', label: 'All Categories' },
  { id: 'CWE-79',  label: 'XSS (CWE-79)' },
  { id: 'CWE-89',  label: 'SQL Injection (CWE-89)' },
  { id: 'CWE-119', label: 'Buffer Overflow (CWE-119)' },
  { id: 'CWE-200', label: 'Info Disclosure (CWE-200)' },
  { id: 'CWE-287', label: 'Improper Auth (CWE-287)' },
  { id: 'CWE-352', label: 'CSRF (CWE-352)' },
  { id: 'CWE-416', label: 'Use After Free (CWE-416)' },
  { id: 'CWE-502', label: 'Deserialization (CWE-502)' },
  { id: 'CWE-787', label: 'Out-of-Bounds Write (CWE-787)' },
  { id: 'CWE-798', label: 'Hardcoded Credentials (CWE-798)' },
];
