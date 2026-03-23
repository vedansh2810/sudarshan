import { NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth.jsx';

const navItems = [
  { to: '/app/dashboard', icon: 'dashboard', label: 'Dashboard' },
  { to: '/app/scan/new', icon: 'radar', label: 'New Scan' },
  { to: '/app/history', icon: 'history', label: 'Scan History' },
];

export default function Layout({ children }) {
  const { user } = useAuth();
  const location = useLocation();
  const initial = user?.username?.[0]?.toUpperCase() || '?';

  const getTitle = () => {
    if (location.pathname.includes('dashboard')) return 'Dashboard';
    if (location.pathname.includes('scan/new')) return 'New Scan';
    if (location.pathname.includes('history')) return 'Scan History';
    if (location.pathname.includes('progress')) return 'Scan Progress';
    if (location.pathname.includes('results')) return 'Scan Results';
    return 'Dashboard';
  };

  return (
    <div className="flex h-screen overflow-hidden font-[Inter,sans-serif]">
      {/* Sidebar */}
      <aside className="w-[250px] bg-bg-secondary border-r border-slate-800 flex flex-col shrink-0">
        <NavLink to="/app/dashboard" className="p-6 flex items-center gap-3 no-underline">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary to-accent-purple flex items-center justify-center shadow-lg shadow-primary/20">
            <span className="material-symbols-outlined text-[#060611] font-bold" style={{ fontVariationSettings: "'FILL' 1" }}>shield_with_heart</span>
          </div>
          <div>
            <h1 className="font-extrabold text-xl tracking-tight leading-none text-white">SUDARSHAN</h1>
            <p className="text-[10px] font-[JetBrains_Mono,monospace] text-primary/70 mt-1 uppercase tracking-tighter">AI Vuln Scanner</p>
          </div>
        </NavLink>

        <nav className="flex-1 px-4 mt-6 space-y-2">
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-3 rounded-xl transition-all group no-underline ${
                  isActive
                    ? 'bg-primary/10 text-primary border border-primary/20'
                    : 'text-slate-400 hover:bg-white/5 hover:text-white border border-transparent'
                }`
              }
            >
              <span className="material-symbols-outlined text-[22px]">{item.icon}</span>
              <span className="text-sm font-semibold">{item.label}</span>
            </NavLink>
          ))}

          <a href="/logout" className="flex items-center gap-3 px-4 py-3 rounded-xl text-slate-400 hover:bg-white/5 hover:text-white transition-all group no-underline mt-4">
            <span className="material-symbols-outlined text-[22px]">logout</span>
            <span className="text-sm font-semibold">Logout</span>
          </a>
        </nav>

        <div className="p-6 border-t border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-[11px] font-[JetBrains_Mono,monospace] text-slate-500">
            <span>VERSION</span>
            <span className="text-primary/60">v2.0.0</span>
          </div>
          <p className="text-[10px] text-slate-600 font-medium leading-tight italic">For authorized use only</p>
        </div>
      </aside>

      {/* Main Area */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Top Bar */}
        <header className="h-16 border-b border-slate-800 flex items-center justify-between px-8 bg-bg-card/50 backdrop-blur-md shrink-0">
          <div className="flex items-center gap-2">
            <span className="text-slate-500 text-sm font-medium italic font-[JetBrains_Mono,monospace]">// root /</span>
            <h2 className="text-white font-bold tracking-tight">{getTitle()}</h2>
          </div>
          <div className="flex items-center gap-3 pl-4 border-l border-slate-800">
            <div className="text-right">
              <p className="text-sm font-bold text-white leading-none">{user?.username || 'User'}</p>
              <p className="text-[11px] text-primary font-[JetBrains_Mono,monospace] mt-1">Security Analyst</p>
            </div>
            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-primary to-accent-purple flex items-center justify-center text-[#060611] font-bold text-lg border-2 border-primary/30">
              {initial}
            </div>
          </div>
        </header>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-8 animate-fade-in-up">
          {children}
        </div>
      </main>
    </div>
  );
}
