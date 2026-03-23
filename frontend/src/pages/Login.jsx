import { useAuth } from '../hooks/useAuth.jsx';

export default function Login() {
  const { setUser } = useAuth();

  const handleGoogleLogin = async () => {
    const configRes = await fetch('/login');
    const html = await configRes.text();
    const urlMatch = html.match(/SUPABASE_URL\s*[:=]\s*['"]([^'"]+)['"]/);
    const keyMatch = html.match(/SUPABASE_ANON_KEY\s*[:=]\s*['"]([^'"]+)['"]/);

    if (!urlMatch || !keyMatch) {
      window.location.href = '/login';
      return;
    }

    const { createClient } = await import('@supabase/supabase-js');
    const supabase = createClient(urlMatch[1], keyMatch[1]);
    const { error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: { redirectTo: window.location.origin + '/auth/callback-react' },
    });
    if (error) console.error('Google login error:', error);
  };

  return (
    <div className="login-bg min-h-screen flex flex-col font-[Space_Grotesk,sans-serif]">
      {/* Top bar */}
      <header className="w-full px-6 lg:px-12 py-6 flex justify-between items-center absolute top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 flex items-center justify-center bg-primary/10 rounded-lg border border-primary/30">
            <span className="material-symbols-outlined text-primary text-xl" style={{ fontVariationSettings: "'FILL' 1" }}>security</span>
          </div>
          <span className="text-white text-xl font-bold tracking-tight">SUDARSHAN</span>
        </div>
      </header>

      {/* Login Card */}
      <main className="flex-1 flex items-center justify-center p-6 mt-12">
        <div className="w-full max-w-[440px] login-card rounded-2xl p-8 lg:p-12 flex flex-col items-center animate-fade-in-up">
          {/* Shield Icon */}
          <div className="mb-8 relative">
            <div className="absolute inset-0 bg-primary/20 blur-2xl rounded-full"></div>
            <div className="relative w-16 h-16 bg-[#060611] border border-primary/50 rounded-2xl flex items-center justify-center shadow-[0_0_20px_rgba(0,229,255,0.3)] animate-pulse-glow">
              <span className="material-symbols-outlined text-primary text-4xl" style={{ fontVariationSettings: "'FILL' 1" }}>security</span>
            </div>
          </div>

          <h1 className="text-4xl font-bold tracking-tighter text-primary neon-text mb-2">SUDARSHAN</h1>
          <p className="text-slate-400 text-sm font-medium mb-10 text-center">AI-Powered Web Vulnerability Scanner</p>

          <div className="w-full space-y-4">
            <button
              onClick={handleGoogleLogin}
              className="w-full flex items-center justify-center gap-3 bg-white hover:bg-slate-100 text-slate-900 font-semibold py-3.5 px-6 rounded-xl transition-all duration-200 shadow-lg hover:shadow-xl hover:-translate-y-0.5 cursor-pointer"
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24">
                <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
                <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
              </svg>
              Continue with Google
            </button>

            <div className="relative flex items-center py-4">
              <div className="flex-grow border-t border-white/5"></div>
              <span className="flex-shrink mx-4 text-slate-500 text-xs uppercase tracking-widest font-bold">Secure Access</span>
              <div className="flex-grow border-t border-white/5"></div>
            </div>
          </div>

          <div className="mt-6 flex flex-col items-center gap-4">
            <p className="text-[11px] text-slate-500 text-center leading-relaxed max-w-[280px]">
              By signing in, you agree to scan only <span className="text-slate-300 font-medium">authorized targets</span> and comply with our Terms of Service.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="w-full p-8 flex flex-col md:flex-row justify-between items-center gap-4">
        <div className="flex items-center gap-2 text-[10px] font-bold tracking-widest text-slate-500 uppercase">
          <span className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse"></span>
          System Status: Operational
        </div>
        <div className="text-slate-600 text-[11px] font-medium tracking-wide">
          © 2025 SUDARSHAN Security Systems
        </div>
      </footer>

      <div className="fixed top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary/50 to-transparent opacity-20"></div>
    </div>
  );
}
