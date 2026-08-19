/* ============================================================
   DXC SOC VULN CORRELATION — Utilities JS
   ============================================================ */

/**
 * Show a toast notification
 * @param {string} message
 * @param {'info'|'success'|'error'|'warning'} type
 * @param {number} duration ms
 */
export function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  const icons = { info: 'ℹ️', success: '✅', error: '❌', warning: '⚠️' };
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type] || icons.info}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'toastOut 0.3s ease forwards';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

/**
 * Format a date string to locale
 */
export function formatDate(dateStr) {
  if (!dateStr) return 'N/A';
  try {
    return new Date(dateStr).toLocaleDateString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric'
    });
  } catch { return dateStr; }
}

/**
 * Truncate text to maxLen characters
 */
export function truncate(str, maxLen = 120) {
  if (!str) return '';
  return str.length > maxLen ? str.slice(0, maxLen) + '…' : str;
}

/**
 * Get severity badge class from CVSS score
 */
export function cvssToSeverity(score) {
  const s = parseFloat(score);
  if (isNaN(s)) return 'info';
  if (s >= 9.0) return 'critical';
  if (s >= 7.0) return 'high';
  if (s >= 4.0) return 'medium';
  if (s > 0)    return 'low';
  return 'info';
}

export function cvssToColor(score) {
  const sev = cvssToSeverity(score);
  const map = {
    critical: '#c62828',
    high:     '#e65100',
    medium:   '#f9a825',
    low:      '#2e7d32',
    info:     '#1565c0',
  };
  return map[sev] || '#999';
}

/**
 * Build an SVG CVSS ring element
 */
export function buildCvssRing(score) {
  const color = cvssToColor(score);
  const radius = 22;
  const circ = 2 * Math.PI * radius;
  const val = Math.min(Math.max(parseFloat(score) || 0, 0), 10);
  const offset = circ - (val / 10) * circ;
  return `
    <div class="cvss-ring">
      <svg viewBox="0 0 56 56">
        <circle class="ring-bg" cx="28" cy="28" r="${radius}"/>
        <circle class="ring-val" cx="28" cy="28" r="${radius}"
          stroke="${color}"
          stroke-dasharray="${circ}"
          stroke-dashoffset="${offset}"/>
      </svg>
      <div class="ring-text" style="color:${color}">${val.toFixed(1)}</div>
    </div>`;
}

/**
 * Build severity badge HTML
 */
export function buildBadge(text, type) {
  return `<span class="badge badge-${type}">${text}</span>`;
}

/**
 * Debounce a function
 */
export function debounce(fn, delay = 300) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

/**
 * Throttle a function (for rate limiting API calls)
 */
export function throttle(fn, limit = 6000) {
  let lastCall = 0;
  let queue = [];
  let timer = null;
  function processQueue() {
    if (!queue.length) { timer = null; return; }
    const { args, resolve } = queue.shift();
    lastCall = Date.now();
    Promise.resolve(fn(...args)).then(resolve);
    timer = setTimeout(processQueue, limit);
  }
  return (...args) => new Promise(resolve => {
    const now = Date.now();
    if (!timer && now - lastCall >= limit) {
      lastCall = now;
      Promise.resolve(fn(...args)).then(resolve);
    } else {
      queue.push({ args, resolve });
      if (!timer) timer = setTimeout(processQueue, limit - (now - lastCall));
    }
  });
}

/**
 * Escape HTML special chars
 */
export function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Simple hash of a string (for dedup)
 */
export function hashStr(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return String(hash);
}

/**
 * Generate a trigger download for a file
 */
export function downloadFile(content, filename, mimeType = 'application/octet-stream') {
  const a = document.createElement('a');
  const blob = new Blob([content], { type: mimeType });
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

/**
 * Session-cached fetch with JSON parsing
 */
const _cache = new Map();
export async function cachedFetch(url, opts = {}) {
  const key = url + JSON.stringify(opts);
  if (_cache.has(key)) return _cache.get(key);
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  const data = await res.json();
  _cache.set(key, data);
  return data;
}

/**
 * Load from sessionStorage cache
 */
export function sessionGet(key) {
  try {
    const item = sessionStorage.getItem(key);
    return item ? JSON.parse(item) : null;
  } catch { return null; }
}

export function sessionSet(key, value) {
  try { sessionStorage.setItem(key, JSON.stringify(value)); } catch {}
}

/**
 * Wait for a delay
 */
export const delay = ms => new Promise(r => setTimeout(r, ms));

/**
 * Format bytes as human readable
 */
export function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}
