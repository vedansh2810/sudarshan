/**
 * API client — thin fetch wrapper for /api/v2/* endpoints.
 * Handles JSON parsing and error extraction.
 */

const BASE = '/api/v2';

async function request(path, options = {}) {
  const url = `${BASE}${path}`;
  const config = {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  };

  const res = await fetch(url, config);

  if (res.status === 401) {
    // Session expired — redirect to login
    window.location.href = '/app/login';
    throw new Error('Session expired');
  }

  const data = await res.json().catch(() => null);

  if (!res.ok) {
    const msg = data?.error || `Request failed (${res.status})`;
    throw new Error(msg);
  }

  return data;
}

export const api = {
  // Auth
  getSession: () => request('/auth/session'),

  // Dashboard
  getDashboard: () => request('/dashboard'),

  // Scans
  listScans: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/scans${qs ? '?' + qs : ''}`);
  },
  createScan: (body) => request('/scans', { method: 'POST', body: JSON.stringify(body) }),
  getScan: (id) => request(`/scans/${id}`),
  deleteScan: (id) => request(`/scans/${id}`, { method: 'DELETE' }),
  getScanResults: (id, params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/scans/${id}/results${qs ? '?' + qs : ''}`);
  },
  getScanStatus: (id) => request(`/scans/${id}/status`),
  pauseScan: (id) => request(`/scans/${id}/pause`, { method: 'POST' }),
  resumeScan: (id) => request(`/scans/${id}/resume`, { method: 'POST' }),
  stopScan: (id) => request(`/scans/${id}/stop`, { method: 'POST' }),

  // Reports
  getReportUrl: (id, fmt) => `${BASE}/scans/${id}/report/${fmt}`,

  // Scans (alias)
  getScans: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/scans${qs ? '?' + qs : ''}`);
  },

  // Checks config
  getChecks: () => request('/checks'),
};
