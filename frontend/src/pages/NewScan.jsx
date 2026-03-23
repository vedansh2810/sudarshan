import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client.jsx';

const CHECKS = [
  { id: 'sql_injection', label: 'SQL Injection', icon: 'database' },
  { id: 'xss', label: 'Cross-Site Scripting', icon: 'code' },
  { id: 'csrf', label: 'CSRF', icon: 'sync_problem' },
  { id: 'security_headers', label: 'Security Headers', icon: 'verified_user' },
  { id: 'directory_traversal', label: 'Directory Traversal', icon: 'folder_open' },
  { id: 'command_injection', label: 'Command Injection', icon: 'terminal' },
  { id: 'idor', label: 'IDOR', icon: 'person_search' },
  { id: 'directory_listing', label: 'Directory Listing', icon: 'list' },
  { id: 'xxe', label: 'XXE Injection', icon: 'data_object' },
  { id: 'ssrf', label: 'SSRF', icon: 'cloud_sync' },
  { id: 'open_redirect', label: 'Open Redirect', icon: 'exit_to_app' },
  { id: 'cors', label: 'CORS Misconfiguration', icon: 'public' },
  { id: 'clickjacking', label: 'Clickjacking', icon: 'mouse' },
];

const SPEEDS = [
  { id: 'safe', label: 'Safe', desc: '3 threads · 1s delay', icon: 'speed' },
  { id: 'balanced', label: 'Balanced', desc: '6 threads · 0.15s delay', icon: 'tune' },
  { id: 'aggressive', label: 'Aggressive', desc: '10 threads · 0.05s delay', icon: 'flash_on' },
];

export default function NewScan() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    target_url: '',
    scan_mode: 'active',
    scan_speed: 'balanced',
    crawl_depth: 3,
    checks: CHECKS.map(c => c.id),
    dvwa_security: 'low',
    authorized: false,
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const toggleCheck = (id) => {
    setForm(prev => ({
      ...prev,
      checks: prev.checks.includes(id) ? prev.checks.filter(c => c !== id) : [...prev.checks, id],
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.authorized) { setError('You must confirm authorization.'); return; }
    if (!form.target_url.trim()) { setError('Target URL is required.'); return; }
    setSubmitting(true);
    setError('');
    try {
      const res = await api.createScan(form);
      navigate(`/app/scan/${res.scan_id}/progress`);
    } catch (err) {
      setError(err.message || 'Failed to start scan.');
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-8 max-w-4xl">
      <div>
        <h3 className="text-4xl font-black text-white tracking-tight">Launch New <span className="text-primary">Scan</span></h3>
        <p className="text-slate-500 font-[JetBrains_Mono,monospace] text-sm mt-2 uppercase tracking-widest">// CONFIGURE YOUR TARGET</p>
      </div>

      <form onSubmit={handleSubmit} className="glass-card rounded-xl p-8 space-y-8">
        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-400 text-sm flex items-center gap-2">
            <span className="material-symbols-outlined text-lg">error</span>{error}
          </div>
        )}

        {/* Target URL */}
        <div>
          <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 font-[JetBrains_Mono,monospace]">Target URL</label>
          <input
            type="text"
            value={form.target_url}
            onChange={e => setForm(p => ({ ...p, target_url: e.target.value }))}
            placeholder="https://example.com"
            className="w-full px-4 py-3.5 bg-bg-primary border border-slate-700 rounded-xl text-white font-[JetBrains_Mono,monospace] text-lg placeholder:text-slate-600 focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/30 transition-all"
          />
        </div>

        {/* Scan Mode */}
        <div>
          <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 font-[JetBrains_Mono,monospace]">Scan Mode</label>
          <div className="grid grid-cols-2 gap-4">
            {['active', 'passive'].map(mode => (
              <button key={mode} type="button"
                onClick={() => setForm(p => ({ ...p, scan_mode: mode }))}
                className={`p-4 rounded-xl border transition-all text-left cursor-pointer ${
                  form.scan_mode === mode
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-slate-700 bg-white/[0.02] text-slate-400 hover:border-slate-500'
                }`}>
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined">{mode === 'active' ? 'flash_on' : 'visibility'}</span>
                  <div>
                    <p className="font-bold capitalize text-white">{mode}</p>
                    <p className="text-xs text-slate-500 mt-1">{mode === 'active' ? 'Full vulnerability testing' : 'Headers & config only'}</p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Scan Speed */}
        <div>
          <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 font-[JetBrains_Mono,monospace]">Scan Speed</label>
          <div className="grid grid-cols-3 gap-4">
            {SPEEDS.map(speed => (
              <button key={speed.id} type="button"
                onClick={() => setForm(p => ({ ...p, scan_speed: speed.id }))}
                className={`p-4 rounded-xl border transition-all text-center cursor-pointer ${
                  form.scan_speed === speed.id
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-slate-700 bg-white/[0.02] text-slate-400 hover:border-slate-500'
                }`}>
                <span className="material-symbols-outlined text-2xl block mb-2">{speed.icon}</span>
                <p className="font-bold text-white text-sm">{speed.label}</p>
                <p className="text-[10px] text-slate-500 mt-1 font-[JetBrains_Mono,monospace]">{speed.desc}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Crawl Depth */}
        <div>
          <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 font-[JetBrains_Mono,monospace]">
            Crawl Depth: <span className="text-primary">{form.crawl_depth}</span>
          </label>
          <input type="range" min="1" max="10" value={form.crawl_depth}
            onChange={e => setForm(p => ({ ...p, crawl_depth: parseInt(e.target.value) }))}
            className="w-full accent-primary cursor-pointer" />
          <div className="flex justify-between text-[10px] text-slate-600 font-[JetBrains_Mono,monospace] mt-1">
            <span>1 (Shallow)</span><span>10 (Deep)</span>
          </div>
        </div>

        {/* Vulnerability Checks */}
        <div>
          <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 font-[JetBrains_Mono,monospace]">Vulnerability Checks</label>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {CHECKS.map(check => (
              <label key={check.id}
                className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                  form.checks.includes(check.id)
                    ? 'border-primary/30 bg-primary/5 text-white'
                    : 'border-slate-800 bg-white/[0.01] text-slate-500 hover:border-slate-600'
                }`}>
                <input type="checkbox" checked={form.checks.includes(check.id)}
                  onChange={() => toggleCheck(check.id)} className="hidden" />
                <span className={`material-symbols-outlined text-lg ${form.checks.includes(check.id) ? 'text-primary' : 'text-slate-600'}`}>{check.icon}</span>
                <span className="text-xs font-semibold">{check.label}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Authorization */}
        <label className="flex items-start gap-3 p-4 rounded-xl border border-amber-500/20 bg-amber-500/5 cursor-pointer">
          <input type="checkbox" checked={form.authorized}
            onChange={e => setForm(p => ({ ...p, authorized: e.target.checked }))}
            className="mt-0.5 accent-primary w-4 h-4 cursor-pointer" />
          <div>
            <p className="text-sm font-bold text-white flex items-center gap-2">
              <span className="material-symbols-outlined text-amber-500 text-lg">gavel</span>
              Authorization Confirmation
            </p>
            <p className="text-xs text-slate-400 mt-1">I confirm I am legally authorized to scan this target and accept full responsibility.</p>
          </div>
        </label>

        {/* Submit */}
        <button type="submit" disabled={submitting}
          className="w-full bg-gradient-to-r from-primary to-cyan-600 text-[#060611] py-4 rounded-xl font-bold text-lg flex items-center justify-center gap-3 hover:scale-[1.02] transition-transform disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer">
          <span className="material-symbols-outlined text-2xl">rocket_launch</span>
          {submitting ? 'Launching Scan...' : 'Launch Scan'}
        </button>
      </form>
    </div>
  );
}
