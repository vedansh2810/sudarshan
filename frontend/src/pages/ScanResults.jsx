import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api/client.jsx';

const sevColors = { critical: '#ff2d55', high: '#ff6400', medium: '#ffb800', low: '#00d46a', info: '#3b82f6' };

export default function ScanResults() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState('all');
  const [vulnType, setVulnType] = useState('all');
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    api.getScanResults(id).then(setData).catch(console.error).finally(() => setLoading(false));
  }, [id]);

  if (loading) return <div className="loading-page"><div className="spinner" /><span>Loading results...</span></div>;
  if (!data) return <div className="loading-page"><span>Failed to load results.</span></div>;

  const { scan, vulnerabilities, counts, all_types } = data;

  const filtered = vulnerabilities.filter(v => {
    if (severity !== 'all' && v.severity !== severity) return false;
    if (vulnType !== 'all' && v.vuln_type !== vulnType) return false;
    return true;
  });

  const scoreColors = { A: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30', B: 'text-primary bg-primary/10 border-primary/30', C: 'text-amber-500 bg-amber-500/10 border-amber-500/30', D: 'text-orange-500 bg-orange-500/10 border-orange-500/30', F: 'text-red-500 bg-red-500/10 border-red-500/30' };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h3 className="text-3xl font-black text-white tracking-tight">Scan <span className="text-primary">Results</span></h3>
          <p className="text-sm font-[JetBrains_Mono,monospace] text-primary mt-2">{scan.target_url}</p>
        </div>
        <div className="flex items-center gap-4">
          {scan.score && (
            <div className={`w-14 h-14 rounded-xl border flex items-center justify-center text-2xl font-black font-[JetBrains_Mono,monospace] ${scoreColors[scan.score] || scoreColors.F}`}>
              {scan.score}
            </div>
          )}
          <div className="flex gap-2">
            <a href={api.getReportUrl(id, 'html')} className="px-4 py-2 rounded-lg border border-slate-700 bg-white/[0.02] text-white text-sm font-semibold hover:border-primary transition-all flex items-center gap-2 no-underline">
              <span className="material-symbols-outlined text-lg">code</span> HTML
            </a>
            <a href={api.getReportUrl(id, 'pdf')} className="px-4 py-2 rounded-lg bg-gradient-to-r from-primary to-cyan-600 text-[#060611] text-sm font-bold flex items-center gap-2 no-underline">
              <span className="material-symbols-outlined text-lg">picture_as_pdf</span> PDF
            </a>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: 'Total', value: scan.vuln_count || 0, color: 'text-white' },
          { label: 'Critical', value: scan.critical_count || 0, color: 'text-red-500' },
          { label: 'High', value: scan.high_count || 0, color: 'text-orange-500' },
          { label: 'Medium', value: scan.medium_count || 0, color: 'text-amber-500' },
          { label: 'Low', value: scan.low_count || 0, color: 'text-emerald-500' },
        ].map((c, i) => (
          <div key={i} className="glass-card rounded-xl p-4 text-center animate-fade-in-up" style={{ animationDelay: `${i * 50}ms` }}>
            <p className="text-xs text-slate-500 uppercase tracking-wider font-bold">{c.label}</p>
            <p className={`text-3xl font-bold font-[JetBrains_Mono,monospace] mt-1 ${c.color}`}>{c.value}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="glass-card rounded-xl p-4 flex flex-wrap gap-4 items-center">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-slate-500 text-lg">filter_list</span>
          <select value={severity} onChange={e => setSeverity(e.target.value)}
            className="bg-bg-primary border border-slate-700 text-slate-300 text-sm rounded-lg px-3 py-2 font-[JetBrains_Mono,monospace] focus:outline-none focus:border-primary">
            <option value="all">All Severities</option>
            {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
          </select>
        </div>
        <select value={vulnType} onChange={e => setVulnType(e.target.value)}
          className="bg-bg-primary border border-slate-700 text-slate-300 text-sm rounded-lg px-3 py-2 font-[JetBrains_Mono,monospace] focus:outline-none focus:border-primary">
          <option value="all">All Types</option>
          {all_types.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
        </select>
        <span className="text-xs text-slate-500 ml-auto font-[JetBrains_Mono,monospace]">{filtered.length} results</span>
      </div>

      {/* Vulnerability List */}
      <div className="space-y-4">
        {filtered.map((v, i) => (
          <div key={v.id || i} className="glass-card rounded-xl overflow-hidden border border-slate-800 animate-fade-in-up" style={{ animationDelay: `${i * 30}ms` }}>
            <button onClick={() => setExpanded(expanded === i ? null : i)}
              className="w-full p-5 flex items-center gap-4 text-left cursor-pointer bg-transparent border-0 text-white hover:bg-white/[0.02] transition-colors">
              <span className="sev-badge shrink-0" style={{
                color: sevColors[v.severity], background: `${sevColors[v.severity]}15`, border: `1px solid ${sevColors[v.severity]}50`
              }}>{v.severity}</span>
              <div className="flex-1 min-w-0">
                <p className="font-bold truncate">{v.name}</p>
                <p className="text-xs text-slate-500 font-[JetBrains_Mono,monospace] mt-1 truncate">{v.affected_url}</p>
              </div>
              {v.cvss_score != null && (
                <span className="text-sm font-bold font-[JetBrains_Mono,monospace] px-2 py-1 rounded bg-white/5 text-slate-300">{v.cvss_score}</span>
              )}
              <span className="material-symbols-outlined text-slate-500">{expanded === i ? 'expand_less' : 'expand_more'}</span>
            </button>

            {expanded === i && (
              <div className="p-5 pt-0 space-y-4 border-t border-slate-800 animate-fade-in-up">
                {v.description && <div><p className="text-xs text-slate-500 font-bold uppercase mb-1">Description</p><p className="text-sm text-slate-300 leading-relaxed">{v.description}</p></div>}
                {v.impact && <div><p className="text-xs text-slate-500 font-bold uppercase mb-1">Impact</p><p className="text-sm text-slate-300 leading-relaxed">{v.impact}</p></div>}
                {v.parameter && <div><p className="text-xs text-slate-500 font-bold uppercase mb-1">Parameter</p><code className="text-sm text-primary bg-primary/5 px-2 py-1 rounded font-[JetBrains_Mono,monospace]">{v.parameter}</code></div>}
                {v.payload && (
                  <div>
                    <p className="text-xs text-slate-500 font-bold uppercase mb-1">Payload</p>
                    <pre className="bg-[#030308] rounded-lg p-4 text-sm font-[JetBrains_Mono,monospace] text-red-400 overflow-x-auto border border-slate-800">{v.payload}</pre>
                  </div>
                )}
                {v.remediation && <div><p className="text-xs text-slate-500 font-bold uppercase mb-1">Remediation</p><p className="text-sm text-emerald-400 leading-relaxed">{v.remediation}</p></div>}
                {v.owasp_category && (
                  <span className="inline-flex items-center px-3 py-1 rounded-full bg-accent-purple/10 border border-accent-purple/30 text-accent-purple text-xs font-bold">
                    OWASP {v.owasp_category}
                  </span>
                )}
              </div>
            )}
          </div>
        ))}
        {filtered.length === 0 && (
          <div className="text-center text-slate-500 py-16">
            <span className="material-symbols-outlined text-4xl mb-2 block">check_circle</span>
            No vulnerabilities found matching your filters.
          </div>
        )}
      </div>
    </div>
  );
}
