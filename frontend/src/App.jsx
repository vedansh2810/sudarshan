import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './hooks/useAuth.jsx';
import Layout from './components/Layout';
import Landing from './pages/Landing';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanProgress from './pages/ScanProgress';
import ScanResults from './pages/ScanResults';
import History from './pages/History';

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="loading-page">
        <div className="spinner" />
        <span>Initializing secure session...</span>
      </div>
    );
  }
  if (!user) return <Navigate to="/app/login" replace />;
  return <Layout>{children}</Layout>;
}

function AppRoutes() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="loading-page">
        <div className="spinner" />
        <span>Loading...</span>
      </div>
    );
  }

  return (
    <Routes>
      {/* Public routes */}
      <Route path="/" element={<Landing />} />
      <Route path="/app/login" element={user ? <Navigate to="/app/dashboard" replace /> : <Login />} />

      {/* Protected routes */}
      <Route path="/app/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="/app/scan/new" element={<ProtectedRoute><NewScan /></ProtectedRoute>} />
      <Route path="/app/scan/:id/progress" element={<ProtectedRoute><ScanProgress /></ProtectedRoute>} />
      <Route path="/app/scan/:id/results" element={<ProtectedRoute><ScanResults /></ProtectedRoute>} />
      <Route path="/app/history" element={<ProtectedRoute><History /></ProtectedRoute>} />

      {/* Fallback */}
      <Route path="/app" element={<Navigate to="/app/dashboard" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  );
}
