import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client.jsx';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts';

const SEV = {
  critical: { color: '#ff2d55', icon: 'dangerous', bg: 'bg-red-500' },
  high: { color: '#ff6400', icon: 'warning', bg: 'bg-amber-500' },
  medium: { color: '#ffb800', icon: 'warning', bg: 'bg-amber-500' },
  low: { color: '#00d46a', icon: 'check_circle', bg: 'bg-emerald-500' },
};

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getDashboard().then(setData).catch(console.error).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading-page"><div className="spinner" /><span>Loading dashboard...</span></div>;
  if (!data) return <div className="loading-page"><span>Failed to load dashboard.</span></div>;

  const { stats, recent_scans, trend, severity_pct } = data;

  const trendData = trend.labels.map((label, i) => ({
    date: label, critical: trend.critical[i] || 0, high: trend.high[i] || 0, medium: trend.medium[i] || 0,
  }));

  const pieData = [
    { name: 'Critical', value: stats.critical, color: '#ff2d55' },
    { name: 'High', value: stats.high, color: '#ff6400' },
    { name: 'Medium', value: stats.medium, color: '#ffb800' },
    { name: 'Low', value: stats.low, color: '#00d46a' },
  ].filter(d => d.value > 0);

  const handleDelete = async (id) => {
    if (!confirm(`Delete scan #${id}?`)) return;
    try {
      await api.deleteScan(id);
      setData(prev => ({ ...prev, recent_scans: prev.recent_scans.filter(s => s.id !== id) }));
    } catch {}
  };

  const statCards = [
    { label: 'Total Scans', value: stats.total_scans, icon: 'analytics', color: 'primary', border: 'border-t-primary' },
    { label: 'Critical', value: stats.critical, icon: 'dangerous', color: 'red-500', border: 'border-t-red-500' },
    { label: 'High / Medium', value: stats.high + stats.medium, icon: 'warning', color: 'amber-500', border: 'border-t-amber-500' },
    { label: 'Low', value: stats.low, icon: 'check_circle', color: 'emerald-500', border: 'border-t-emerald-500' },
  ];

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex items-end justify-between">
        <div>
          <h3 className="text-4xl font-black text-white tracking-tight">Threat Dashboard</h3>
          <p className="text-slate-500 font-[JetBrains_Mono,monospace] text-sm mt-2 uppercase tracking-widest">// REAL-TIME SECURITY OVERVIEW</p>
        </div>
        <Link to="/app/scan/new" className="bg-gradient-to-r from-primary to-cyan-600 text-[#060611] px-6 py-2.5 rounded-lg font-bold flex items-center gap-2 hover:opacity-90 transition-opacity no-underline">
          <span className="material-symbols-outlined">add_moderator</span>
          NEW SCAN
        </Link>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statCards.map((card, i) => (
          <div key={i} className={`glass-card p-6 rounded-xl border-t-2 ${card.border} hover:-translate-y-1 transition-transform duration-300 group animate-fade-in-up`} style={{ animationDelay: `${i * 100}ms` }}>
            <div className="flex justify-between items-start mb-4">
              <span className={`material-symbols-outlined text-${card.color} group-hover:scale-110 transition-transform`}>{card.icon}</span>
            </div>
            <p className="text-slate-400 text-xs font-bold uppercase tracking-wider">{card.label}</p>
            <p className="text-4xl font-[JetBrains_Mono,monospace] font-bold text-white mt-1">{card.value}</p>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-10 gap-8">
        <div className="lg:col-span-6 glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between mb-8">
            <h4 className="text-lg font-bold text-white">Vulnerability Trend</h4>
          </div>
          <div style={{ height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="date" tick={{ fill: '#4a5a6a', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
                <YAxis tick={{ fill: '#4a5a6a', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
                <Tooltip contentStyle={{ background: '#0d0d24', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }} />
                <Line type="monotone" dataKey="critical" stroke="#ff2d55" strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="high" stroke="#ff6400" strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="medium" stroke="#ffb800" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-4 glass-card p-6 rounded-xl">
          <h4 className="text-lg font-bold text-white mb-8">Severity Breakdown</h4>
          <div className="flex flex-col items-center">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={170}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} dataKey="value" strokeWidth={2} stroke="#0d0d24">
                    {pieData.map((d, i) => <Cell key={i} fill={d.color} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#0d0d24', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-center text-slate-500 py-10">No vulnerability data yet</div>
            )}
            <div className="w-full mt-4 space-y-3">
              {['critical', 'high', 'medium', 'low'].map(sev => (
                <div key={sev}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full" style={{ background: SEV[sev].color }}></div>
                      <span className="text-xs text-slate-400 font-medium capitalize">{sev}</span>
                    </div>
                    <span className="text-xs font-[JetBrains_Mono,monospace] text-white">{stats[sev]}</span>
                  </div>
                  <div className="w-full bg-white/5 rounded-full h-1.5 overflow-hidden mt-1">
                    <div className="h-full rounded-full transition-all duration-500" style={{ width: `${severity_pct[sev]}%`, background: SEV[sev].color }}></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="glass-card rounded-xl overflow-hidden border border-slate-800">
        <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-white/5">
          <h4 className="text-lg font-bold text-white uppercase tracking-tight">Recent Scans</h4>
          <Link to="/app/history" className="text-sm text-primary hover:underline font-semibold no-underline">View All →</Link>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-slate-900/50 text-[11px] font-[JetBrains_Mono,monospace] text-slate-500 uppercase tracking-widest border-b border-slate-800">
              <tr>
                <th className="px-6 py-4 font-normal">Target</th>
                <th className="px-6 py-4 font-normal">Status</th>
                <th className="px-6 py-4 font-normal">Score</th>
                <th className="px-6 py-4 font-normal text-center">Findings</th>
                <th className="px-6 py-4 font-normal">Date</th>
                <th className="px-6 py-4 font-normal text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {recent_scans.map(scan => (
                <tr key={scan.id} className="hover:bg-white/[0.02] transition-colors group">
                  <td className="px-6 py-5">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded bg-primary/10 flex items-center justify-center text-primary">
                        <span className="material-symbols-outlined text-xl">language</span>
                      </div>
                      <p className="text-sm font-bold text-white leading-tight font-[JetBrains_Mono,monospace]">
                        {scan.target_url?.length > 35 ? scan.target_url.slice(0, 35) + '…' : scan.target_url}
                      </p>
                    </div>
                  </td>
                  <td className="px-6 py-5">
                    <span className={`status-pill w-fit ${
                      scan.status === 'running' ? 'bg-primary/20 text-primary border border-primary/30' :
                      scan.status === 'complete' ? 'bg-emerald-500/20 text-emerald-500 border border-emerald-500/30' :
                      scan.status === 'error' ? 'bg-red-500/20 text-red-500 border border-red-500/30' :
                      'bg-amber-500/20 text-amber-500 border border-amber-500/30'
                    }`}>
                      {scan.status === 'running' && <span className="w-1 h-1 bg-primary rounded-full animate-pulse"></span>}
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-6 py-5">
                    {scan.score ? (
                      <div className={`score-badge ${
                        scan.score === 'A' ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-500' :
                        scan.score === 'B' ? 'bg-primary/10 border border-primary/30 text-primary' :
                        scan.score === 'C' ? 'bg-amber-500/10 border border-amber-500/30 text-amber-500' :
                        scan.score === 'D' ? 'bg-orange-500/10 border border-orange-500/30 text-orange-500' :
                        'bg-red-500/10 border border-red-500/30 text-red-500'
                      }`}>{scan.score}</div>
                    ) : '—'}
                  </td>
                  <td className="px-6 py-5 text-center font-[JetBrains_Mono,monospace] text-sm">
                    <span style={{ color: '#ff2d55' }}>{scan.critical_count}</span>
                    <span className="text-slate-600 mx-1">/</span>
                    <span style={{ color: '#ff6400' }}>{scan.high_count}</span>
                    <span className="text-slate-600 mx-1">/</span>
                    <span style={{ color: '#ffb800' }}>{scan.medium_count}</span>
                  </td>
                  <td className="px-6 py-5 text-xs text-slate-400 font-[JetBrains_Mono,monospace]">
                    {scan.started_at?.slice(0, 16)?.replace('T', ' ')}
                  </td>
                  <td className="px-6 py-5 text-right">
                    <div className="flex items-center justify-end gap-2">
                      {(scan.status === 'running' || scan.status === 'paused') && (
                        <Link to={`/app/scan/${scan.id}/progress`} className="p-1.5 hover:bg-white/10 rounded transition-colors text-slate-500 hover:text-primary">
                          <span className="material-symbols-outlined text-lg">monitoring</span>
                        </Link>
                      )}
                      <Link to={`/app/scan/${scan.id}/results`} className="p-1.5 hover:bg-white/10 rounded transition-colors text-slate-500 hover:text-primary">
                        <span className="material-symbols-outlined text-lg">visibility</span>
                      </Link>
                      <a href={api.getReportUrl(scan.id, 'pdf')} className="p-1.5 hover:bg-white/10 rounded transition-colors text-slate-500 hover:text-white">
                        <span className="material-symbols-outlined text-lg">download</span>
                      </a>
                      <button onClick={() => handleDelete(scan.id)} className="p-1.5 hover:bg-red-500/10 rounded transition-colors text-slate-500 hover:text-red-500 cursor-pointer border-0 bg-transparent">
                        <span className="material-symbols-outlined text-lg">delete</span>
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {recent_scans.length === 0 && (
                <tr><td colSpan={6} className="text-center text-slate-500 py-12">No scans yet. Start your first scan!</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
