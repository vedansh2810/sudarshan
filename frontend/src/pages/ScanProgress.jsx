import { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api/client.jsx';

export default function ScanProgress() {
  const { id } = useParams();
  const [status, setStatus] = useState(null);
  const [logs, setLogs] = useState([]);
  const [findings, setFindings] = useState([]);
  const logRef = useRef(null);

  useEffect(() => {
    const poll = setInterval(async () => {
      try {
        const st = await api.getScanStatus(id);
        setStatus(st);
        if (['completed', 'stopped', 'error'].includes(st.status)) clearInterval(poll);
      } catch {}
    }, 2000);
    return () => clearInterval(poll);
  }, [id]);

  useEffect(() => {
    const evtSrc = new EventSource(`/api/v2/scans/${id}/stream`);
    evtSrc.addEventListener('log', e => {
      const data = JSON.parse(e.data);
      setLogs(prev => [...prev, data]);
    });
    evtSrc.addEventListener('finding', e => {
      const data = JSON.parse(e.data);
      setFindings(prev => [...prev, data]);
    });
    evtSrc.addEventListener('progress', e => {
      const data = JSON.parse(e.data);
      setStatus(prev => ({ ...prev, ...data }));
    });
    evtSrc.addEventListener('complete', e => {
      const data = JSON.parse(e.data);
      setStatus(prev => ({ ...prev, status: 'completed', ...data }));
    });
    return () => evtSrc.close();
  }, [id]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const handleControl = async (action) => {
    try { await api[`${action}Scan`](id); } catch {}
  };

  const total = status?.total_urls || 0;
  const tested = status?.tested_urls || 0;
  const pct = total > 0 ? Math.round((tested / total) * 100) : 0;
  const isRunning = status?.status === 'running';
  const isPaused = status?.status === 'paused';
  const isDone = ['completed', 'stopped', 'error'].includes(status?.status);

  const sevColors = { critical: '#ff2d55', high: '#ff6400', medium: '#ffb800', low: '#00d46a', info: '#3b82f6' };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-3xl font-black text-white tracking-tight">Scan <span className="text-primary">Progress</span></h3>
          <p className="text-slate-500 font-[JetBrains_Mono,monospace] text-sm mt-2">
            Scan #{id} · <span className={`${isRunning ? 'text-primary' : isPaused ? 'text-amber-500' : isDone ? 'text-emerald-500' : 'text-slate-400'}`}>{status?.status || 'loading...'}</span>
          </p>
        </div>
        {isDone && (
          <Link to={`/app/scan/${id}/results`} className="bg-gradient-to-r from-primary to-cyan-600 text-[#060611] px-6 py-2.5 rounded-lg font-bold flex items-center gap-2 no-underline">
            <span className="material-symbols-outlined">assessment</span> View Results
          </Link>
        )}
      </div>

      {/* Progress */}
      <div className="glass-card rounded-xl p-6">
        <div className="flex items-center gap-8 mb-6">
          {/* Circular progress */}
          <div className="relative w-24 h-24 shrink-0">
            <svg className="w-24 h-24 -rotate-90">
              <circle cx="48" cy="48" r="42" fill="transparent" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />
              <circle cx="48" cy="48" r="42" fill="transparent" stroke="var(--color-primary)" strokeWidth="6"
                strokeDasharray={264} strokeDashoffset={264 - (264 * pct / 100)} strokeLinecap="round"
                className="transition-all duration-500" />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-xl font-bold font-[JetBrains_Mono,monospace] text-white">{pct}%</span>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-5 gap-6 flex-1">
            {[
              { label: 'Phase', value: status?.phase || '—', icon: 'sync' },
              { label: 'URLs Found', value: total, icon: 'language' },
              { label: 'URLs Tested', value: tested, icon: 'check_circle' },
              { label: 'Findings', value: status?.findings || findings.length, icon: 'bug_report' },
              { label: 'Elapsed', value: `${status?.elapsed || 0}s`, icon: 'timer' },
            ].map((s, i) => (
              <div key={i} className="text-center">
                <span className="material-symbols-outlined text-primary text-lg">{s.icon}</span>
                <p className="text-xs text-slate-500 uppercase tracking-wider font-bold mt-1">{s.label}</p>
                <p className="text-lg font-bold font-[JetBrains_Mono,monospace] text-white">{s.value}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Controls */}
        <div className="flex gap-3">
          <button onClick={() => handleControl('pause')} disabled={!isRunning}
            className="px-5 py-2 rounded-lg font-semibold text-sm flex items-center gap-2 border border-amber-500/30 bg-amber-500/10 text-amber-500 disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed transition-all hover:bg-amber-500/20">
            <span className="material-symbols-outlined text-lg">pause</span> Pause
          </button>
          <button onClick={() => handleControl('resume')} disabled={!isPaused}
            className="px-5 py-2 rounded-lg font-semibold text-sm flex items-center gap-2 border border-emerald-500/30 bg-emerald-500/10 text-emerald-500 disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed transition-all hover:bg-emerald-500/20">
            <span className="material-symbols-outlined text-lg">play_arrow</span> Resume
          </button>
          <button onClick={() => handleControl('stop')} disabled={isDone}
            className="px-5 py-2 rounded-lg font-semibold text-sm flex items-center gap-2 border border-red-500/30 bg-red-500/10 text-red-500 disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed transition-all hover:bg-red-500/20">
            <span className="material-symbols-outlined text-lg">stop</span> Stop
          </button>
        </div>
      </div>

      {/* Live Findings */}
      {findings.length > 0 && (
        <div className="glass-card rounded-xl p-6">
          <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <span className="material-symbols-outlined text-primary">report_problem</span> Live Findings
          </h4>
          <div className="space-y-3">
            {findings.map((f, i) => (
              <div key={i} className="flex items-center gap-4 p-3 rounded-lg bg-white/[0.02] border border-slate-800 animate-slide-in">
                <span className="sev-badge" style={{
                  color: sevColors[f.severity] || '#3b82f6',
                  background: `${sevColors[f.severity] || '#3b82f6'}15`,
                  border: `1px solid ${sevColors[f.severity] || '#3b82f6'}50`,
                }}>{f.severity}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-white truncate">{f.name}</p>
                  <p className="text-xs text-slate-500 font-[JetBrains_Mono,monospace] truncate">{f.url}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Log Viewer */}
      <div className="glass-card rounded-xl p-6">
        <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <span className="material-symbols-outlined text-primary">terminal</span> Scan Log
        </h4>
        <div ref={logRef} className="log-viewer" style={{ maxHeight: 350 }}>
          {logs.map((log, i) => (
            <div key={i} className={`py-0.5 ${
              log.level === 'error' ? 'text-red-400' :
              log.level === 'warning' ? 'text-amber-400' :
              log.level === 'success' ? 'text-emerald-400' :
              'text-slate-400'
            }`}>
              <span className="text-slate-600 mr-2">[{log.timestamp || '—'}]</span>
              {log.message}
            </div>
          ))}
          {logs.length === 0 && <span className="text-slate-600">Waiting for scan events...</span>}
        </div>
      </div>
    </div>
  );
}
