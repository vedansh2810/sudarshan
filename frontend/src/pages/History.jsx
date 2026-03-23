import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client.jsx';

export default function History() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [page, setPage] = useState(1);

  const fetchData = async (pg = 1) => {
    setLoading(true);
    try {
      const res = await api.getScans({ search, date_from: dateFrom, date_to: dateTo, page: pg });
      setData(res);
      setPage(pg);
    } catch (err) { console.error(err); }
    setLoading(false);
  };

  useEffect(() => { fetchData(); }, []);

  const handleFilter = (e) => { e.preventDefault(); fetchData(1); };

  const handleDelete = async (id) => {
    if (!confirm(`Delete scan #${id}?`)) return;
    try {
      await api.deleteScan(id);
      fetchData(page);
    } catch {}
  };

  const scoreColors = { A: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30', B: 'text-primary bg-primary/10 border-primary/30', C: 'text-amber-500 bg-amber-500/10 border-amber-500/30', D: 'text-orange-500 bg-orange-500/10 border-orange-500/30', F: 'text-red-500 bg-red-500/10 border-red-500/30' };

  return (
    <div className="space-y-8">
      <div>
        <h3 className="text-4xl font-black text-white tracking-tight">Scan <span className="text-primary">History</span></h3>
        <p className="text-slate-500 font-[JetBrains_Mono,monospace] text-sm mt-2 uppercase tracking-widest">// ALL PREVIOUS SCANS</p>
      </div>

      {/* Filter Bar */}
      <form onSubmit={handleFilter} className="glass-card rounded-xl p-4 flex flex-wrap gap-4 items-end">
        <div className="flex-1 min-w-[200px]">
          <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Search URL</label>
          <div className="relative">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-lg">search</span>
            <input type="text" value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search by URL..."
              className="w-full pl-10 pr-4 py-2.5 bg-bg-primary border border-slate-700 rounded-lg text-sm text-slate-300 focus:outline-none focus:border-primary font-[JetBrains_Mono,monospace]" />
          </div>
        </div>
        <div>
          <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">From</label>
          <input type="date" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
            className="px-3 py-2.5 bg-bg-primary border border-slate-700 rounded-lg text-sm text-slate-300 focus:outline-none focus:border-primary" />
        </div>
        <div>
          <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">To</label>
          <input type="date" value={dateTo} onChange={e => setDateTo(e.target.value)}
            className="px-3 py-2.5 bg-bg-primary border border-slate-700 rounded-lg text-sm text-slate-300 focus:outline-none focus:border-primary" />
        </div>
        <button type="submit" className="px-5 py-2.5 bg-primary/10 border border-primary/30 rounded-lg text-primary font-semibold text-sm hover:bg-primary/20 transition-colors cursor-pointer flex items-center gap-2">
          <span className="material-symbols-outlined text-lg">filter_list</span> Filter
        </button>
      </form>

      {/* Table */}
      {loading ? (
        <div className="loading-page"><div className="spinner" /><span>Loading scans...</span></div>
      ) : data ? (
        <>
          <div className="glass-card rounded-xl overflow-hidden border border-slate-800">
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="bg-slate-900/50 text-[11px] font-[JetBrains_Mono,monospace] text-slate-500 uppercase tracking-widest border-b border-slate-800">
                  <tr>
                    <th className="px-6 py-4 font-normal">Target</th>
                    <th className="px-6 py-4 font-normal">Status</th>
                    <th className="px-6 py-4 font-normal">Score</th>
                    <th className="px-4 py-4 font-normal text-center">Crit</th>
                    <th className="px-4 py-4 font-normal text-center">High</th>
                    <th className="px-4 py-4 font-normal text-center">Med</th>
                    <th className="px-4 py-4 font-normal text-center">Low</th>
                    <th className="px-6 py-4 font-normal">Duration</th>
                    <th className="px-6 py-4 font-normal">Date</th>
                    <th className="px-6 py-4 font-normal text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {data.scans.map(scan => (
                    <tr key={scan.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="px-6 py-5">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded bg-primary/10 flex items-center justify-center text-primary shrink-0">
                            <span className="material-symbols-outlined text-lg">language</span>
                          </div>
                          <p className="text-sm font-bold text-white font-[JetBrains_Mono,monospace] truncate max-w-[200px]">{scan.target_url}</p>
                        </div>
                      </td>
                      <td className="px-6 py-5">
                        <span className={`status-pill w-fit ${
                          scan.status === 'running' ? 'bg-primary/20 text-primary border border-primary/30' :
                          scan.status === 'completed' ? 'bg-emerald-500/20 text-emerald-500 border border-emerald-500/30' :
                          scan.status === 'error' ? 'bg-red-500/20 text-red-500 border border-red-500/30' :
                          'bg-amber-500/20 text-amber-500 border border-amber-500/30'
                        }`}>
                          {scan.status === 'running' && <span className="w-1 h-1 bg-primary rounded-full animate-pulse"></span>}
                          {scan.status === 'completed' ? 'complete' : scan.status}
                        </span>
                      </td>
                      <td className="px-6 py-5">
                        {scan.score ? (
                          <div className={`score-badge ${scoreColors[scan.score] || scoreColors.F} border`}>{scan.score}</div>
                        ) : '—'}
                      </td>
                      <td className="px-4 py-5 text-center font-[JetBrains_Mono,monospace] text-sm text-red-500">{scan.critical_count}</td>
                      <td className="px-4 py-5 text-center font-[JetBrains_Mono,monospace] text-sm text-orange-500">{scan.high_count}</td>
                      <td className="px-4 py-5 text-center font-[JetBrains_Mono,monospace] text-sm text-amber-500">{scan.medium_count}</td>
                      <td className="px-4 py-5 text-center font-[JetBrains_Mono,monospace] text-sm text-emerald-500">{scan.low_count}</td>
                      <td className="px-6 py-5 text-xs text-slate-400 font-[JetBrains_Mono,monospace]">{scan.duration ? `${scan.duration}s` : '—'}</td>
                      <td className="px-6 py-5 text-xs text-slate-400">{scan.started_at?.slice(0, 10)}</td>
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
                  {data.scans.length === 0 && (
                    <tr><td colSpan={10} className="text-center text-slate-500 py-12">No scans found.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pagination */}
          {data.pagination.total_pages > 1 && (
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-500 font-[JetBrains_Mono,monospace]">
                Showing {(page - 1) * data.pagination.per_page + 1}–{Math.min(page * data.pagination.per_page, data.pagination.total)} of {data.pagination.total} scans
              </span>
              <div className="flex gap-2">
                <button onClick={() => fetchData(page - 1)} disabled={page <= 1}
                  className="px-3 py-2 rounded-lg border border-slate-700 bg-white/[0.02] text-slate-400 text-sm disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed hover:border-primary transition-colors">
                  <span className="material-symbols-outlined text-lg">chevron_left</span>
                </button>
                {Array.from({ length: data.pagination.total_pages }, (_, i) => i + 1).slice(Math.max(0, page - 3), page + 2).map(p => (
                  <button key={p} onClick={() => fetchData(p)}
                    className={`px-3 py-2 rounded-lg text-sm font-bold cursor-pointer transition-colors ${
                      p === page ? 'bg-primary/20 border border-primary/30 text-primary' : 'border border-slate-700 bg-white/[0.02] text-slate-400 hover:border-primary'
                    }`}>{p}</button>
                ))}
                <button onClick={() => fetchData(page + 1)} disabled={page >= data.pagination.total_pages}
                  className="px-3 py-2 rounded-lg border border-slate-700 bg-white/[0.02] text-slate-400 text-sm disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed hover:border-primary transition-colors">
                  <span className="material-symbols-outlined text-lg">chevron_right</span>
                </button>
              </div>
            </div>
          )}
        </>
      ) : null}
    </div>
  );
}
