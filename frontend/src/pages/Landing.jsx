import { Link } from 'react-router-dom';

export default function Landing() {
  return (
    <div className="relative min-h-screen overflow-x-hidden grid-pattern font-[Space_Grotesk,sans-serif]">
      {/* Navigation */}
      <header className="fixed top-0 w-full z-50 border-b border-white/10 bg-[#060611]/80 backdrop-blur-md">
        <nav className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center shadow-[0_0_20px_rgba(0,229,255,0.3)]">
              <span className="material-symbols-outlined text-[#060611] font-bold text-lg">shield</span>
            </div>
            <span className="text-2xl font-bold tracking-tighter text-white">SUDARSHAN</span>
          </div>
          <div className="hidden md:flex items-center gap-10">
            <a className="text-sm font-medium hover:text-primary transition-colors text-slate-300" href="#features">Features</a>
            <a className="text-sm font-medium hover:text-primary transition-colors text-slate-300" href="#how-it-works">How It Works</a>
            <a className="text-sm font-medium hover:text-primary transition-colors text-slate-300" href="#stats">Stats</a>
          </div>
          <div className="flex items-center gap-4">
            <Link to="/app/login" className="px-5 py-2 text-sm font-semibold text-slate-300 hover:text-primary transition-colors">Sign In</Link>
            <Link to="/app/login" className="bg-primary text-[#060611] px-6 py-2.5 rounded-lg text-sm font-bold hover:brightness-110 transition-all shadow-[0_0_20px_rgba(0,229,255,0.3)]">
              Get Started
            </Link>
          </div>
        </nav>
      </header>

      {/* Hero Section */}
      <section className="pt-40 pb-20 px-6 max-w-7xl mx-auto">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          <div className="flex flex-col gap-8 animate-fade-in-up">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 w-fit">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
              </span>
              <span className="text-[10px] uppercase font-bold tracking-widest text-primary">v2.0 Now Live</span>
            </div>
            <div className="space-y-4">
              <h1 className="text-6xl md:text-8xl font-bold tracking-tighter text-white leading-[0.9] hero-glow">
                SUDARSHAN
              </h1>
              <p className="text-xl md:text-2xl text-slate-400 font-light max-w-lg leading-relaxed">
                AI-Powered Web Vulnerability Scanner — <span className="text-white font-medium">Protect Your Web Applications</span> in real-time.
              </p>
            </div>
            <div className="flex flex-wrap gap-4">
              <Link to="/app/login" className="bg-gradient-to-r from-primary to-cyan-600 text-[#060611] px-8 py-4 rounded-xl font-bold text-lg hover:scale-105 transition-transform shadow-xl inline-flex items-center gap-2">
                <span className="material-symbols-outlined">rocket_launch</span>
                Start Scanning Free
              </Link>
              <a href="#features" className="glass-panel text-white px-8 py-4 rounded-xl font-bold text-lg hover:bg-white/10 transition-all flex items-center gap-2">
                <span className="material-symbols-outlined">play_circle</span>
                Learn More
              </a>
            </div>
            <div className="flex items-center gap-4 text-slate-500 text-sm">
              <div className="flex -space-x-2">
                <div className="w-8 h-8 rounded-full border-2 border-[#060611] bg-gradient-to-br from-primary/40 to-accent-purple/40"></div>
                <div className="w-8 h-8 rounded-full border-2 border-[#060611] bg-gradient-to-br from-accent-purple/40 to-primary/40"></div>
                <div className="w-8 h-8 rounded-full border-2 border-[#060611] bg-gradient-to-br from-primary/60 to-cyan-600/40"></div>
              </div>
              <span>Trusted by security teams worldwide</span>
            </div>
          </div>

          {/* Dashboard Preview */}
          <div className="relative group animate-fade-in-up delay-200" style={{ animationDelay: '200ms' }}>
            <div className="absolute -inset-1 bg-gradient-to-r from-primary/30 to-accent-purple/30 rounded-2xl blur-2xl opacity-50 group-hover:opacity-100 transition duration-1000"></div>
            <div className="relative glass-panel rounded-2xl p-4 overflow-hidden shadow-2xl">
              <div className="flex items-center gap-2 mb-4 px-2">
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-500/50"></div>
                  <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/50"></div>
                  <div className="w-2.5 h-2.5 rounded-full bg-green-500/50"></div>
                </div>
                <div className="ml-4 h-5 w-32 bg-white/5 rounded"></div>
              </div>
              <div className="aspect-[4/3] bg-[#060611]/50 rounded-lg flex flex-col gap-4 p-6 overflow-hidden">
                <div className="flex justify-between items-end gap-2 h-32">
                  <div className="w-full bg-primary/20 rounded-t animate-pulse" style={{ height: '40%' }}></div>
                  <div className="w-full bg-primary/40 rounded-t animate-pulse" style={{ height: '70%', animationDelay: '0.2s' }}></div>
                  <div className="w-full bg-primary/60 rounded-t animate-pulse" style={{ height: '55%', animationDelay: '0.4s' }}></div>
                  <div className="w-full bg-primary/30 rounded-t animate-pulse" style={{ height: '90%', animationDelay: '0.6s' }}></div>
                  <div className="w-full bg-primary/50 rounded-t animate-pulse" style={{ height: '65%', animationDelay: '0.8s' }}></div>
                </div>
                <div className="flex-1 grid grid-cols-2 gap-4">
                  <div className="glass-panel p-4 rounded-xl flex flex-col gap-2">
                    <span className="text-[10px] text-slate-500 uppercase font-bold tracking-widest">Active Threats</span>
                    <span className="text-2xl font-bold text-sev-critical">0</span>
                  </div>
                  <div className="glass-panel p-4 rounded-xl flex flex-col gap-2">
                    <span className="text-[10px] text-slate-500 uppercase font-bold tracking-widest">Security Score</span>
                    <span className="text-2xl font-bold text-primary">A+</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Bar */}
      <section className="max-w-7xl mx-auto px-6 py-12" id="stats">
        <div className="glass-panel rounded-2xl grid grid-cols-2 md:grid-cols-4 divide-x divide-white/10 overflow-hidden">
          {[
            { value: '13+', label: 'Vulnerability Checks' },
            { value: 'Real-Time', label: 'Scanning Speed' },
            { value: 'ML-Powered', label: 'Security Analysis' },
            { value: '99.9%', label: 'Platform Uptime' },
          ].map((s, i) => (
            <div key={i} className="p-8 text-center flex flex-col gap-1 animate-fade-in-up" style={{ animationDelay: `${i * 100}ms` }}>
              <span className="text-3xl font-bold text-white">{s.value}</span>
              <span className="text-xs text-slate-500 font-bold uppercase tracking-widest">{s.label}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section className="max-w-7xl mx-auto px-6 py-24" id="features">
        <div className="text-center mb-16 space-y-4">
          <h2 className="text-4xl md:text-5xl font-bold text-white tracking-tight">Advanced Cybersecurity Features</h2>
          <p className="text-slate-400 max-w-2xl mx-auto">Our AI-driven engine provides enterprise-grade protection for modern digital assets.</p>
        </div>
        <div className="grid md:grid-cols-2 gap-6">
          {[
            { icon: 'shield', title: 'Deep Vulnerability Scanning', desc: '13 active checks including SQL Injection, XSS, CSRF, SSRF, XXE, Command Injection, and more.', color: 'primary' },
            { icon: 'query_stats', title: 'Real-Time Monitoring', desc: 'Live SSE streaming with pause/resume controls. Watch vulnerabilities discovered in real-time.', color: 'accent-purple' },
            { icon: 'psychology', title: 'AI False Positive Reduction', desc: 'ML ensemble classifier with RandomForest + GradientBoosting for accurate threat detection.', color: 'primary' },
            { icon: 'description', title: 'Professional Reports', desc: 'Export detailed security findings in PDF and HTML formats, ready for compliance reviews.', color: 'accent-purple' },
          ].map((f, i) => (
            <div key={i} className="glass-panel p-8 rounded-2xl border-white/5 hover:border-primary/30 transition-all group neon-border animate-fade-in-up" style={{ animationDelay: `${i * 150}ms` }}>
              <div className={`w-12 h-12 rounded-lg bg-${f.color}/10 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform`}>
                <span className={`material-symbols-outlined text-${f.color} text-3xl`}>{f.icon}</span>
              </div>
              <h3 className="text-xl font-bold text-white mb-3">{f.title}</h3>
              <p className="text-slate-400 leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* How It Works */}
      <section className="max-w-7xl mx-auto px-6 py-24 relative" id="how-it-works">
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-20">
          <div className="w-96 h-96 bg-primary blur-[120px] rounded-full"></div>
        </div>
        <div className="relative">
          <div className="text-center mb-16 space-y-4">
            <h2 className="text-4xl md:text-5xl font-bold text-white tracking-tight">Three Steps to Security</h2>
            <p className="text-slate-400">Go from vulnerable to validated in minutes.</p>
          </div>
          <div className="grid md:grid-cols-3 gap-12">
            {[
              { num: '1', title: 'Configure Scan', desc: 'Enter your target URL and define scanning depth, speed, and vulnerability checks.' },
              { num: '2', title: 'Automated Analysis', desc: 'Our AI engine crawls and probes your app, executing hundreds of security test vectors.' },
              { num: '3', title: 'Get Results', desc: 'Download comprehensive reports and follow prioritized remediation guidelines.' },
            ].map((step, i) => (
              <div key={i} className="text-center space-y-6 animate-fade-in-up" style={{ animationDelay: `${i * 200}ms` }}>
                <div className="w-16 h-16 rounded-full bg-[#060611] border-2 border-primary/30 flex items-center justify-center mx-auto text-2xl font-bold text-primary shadow-[0_0_20px_rgba(0,229,255,0.2)]">
                  {step.num}
                </div>
                <h4 className="text-xl font-bold text-white">{step.title}</h4>
                <p className="text-slate-400">{step.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="max-w-7xl mx-auto px-6 py-24">
        <div className="glass-panel rounded-2xl p-12 md:p-16 text-center relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-r from-primary/5 to-accent-purple/5"></div>
          <div className="relative">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">Ready to Secure Your Applications?</h2>
            <p className="text-slate-400 mb-8 max-w-xl mx-auto">Start scanning your web applications for vulnerabilities today. No credit card required.</p>
            <Link to="/app/login" className="bg-gradient-to-r from-primary to-cyan-600 text-[#060611] px-10 py-4 rounded-xl font-bold text-lg hover:scale-105 transition-transform shadow-xl inline-flex items-center gap-2">
              <span className="material-symbols-outlined">security</span>
              Start Free Scan
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/10 pt-20 pb-10 px-6">
        <div className="max-w-7xl mx-auto grid md:grid-cols-4 gap-12 mb-20">
          <div className="col-span-2 space-y-6">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 bg-primary rounded flex items-center justify-center">
                <span className="material-symbols-outlined text-[14px] text-[#060611] font-bold">shield</span>
              </div>
              <span className="text-xl font-bold tracking-tighter text-white">SUDARSHAN</span>
            </div>
            <p className="text-slate-400 max-w-xs leading-relaxed">
              Redefining web security through autonomous AI vulnerability analysis. Built for the modern web.
            </p>
          </div>
          <div>
            <h5 className="text-white font-bold mb-6">Product</h5>
            <ul className="space-y-4 text-slate-400 text-sm">
              <li><a className="hover:text-primary transition-colors" href="#features">Features</a></li>
              <li><a className="hover:text-primary transition-colors" href="#how-it-works">How It Works</a></li>
              <li><Link className="hover:text-primary transition-colors" to="/app/login">Dashboard</Link></li>
            </ul>
          </div>
          <div>
            <h5 className="text-white font-bold mb-6">Resources</h5>
            <ul className="space-y-4 text-slate-400 text-sm">
              <li><a className="hover:text-primary transition-colors" href="#">Documentation</a></li>
              <li><a className="hover:text-primary transition-colors" href="#">API Reference</a></li>
              <li><a className="hover:text-primary transition-colors" href="#">Security</a></li>
            </ul>
          </div>
        </div>
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4 pt-10 border-t border-white/5">
          <p className="text-xs text-slate-500 uppercase tracking-widest font-bold">© 2025 Sudarshan. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}
