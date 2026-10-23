import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  CircularProgress,
  InputAdornment,
  IconButton,
  Chip,
  Divider,
} from '@mui/material';
import {
  ShieldCheck,
  Lock,
  User,
  Eye,
  EyeOff,
  KeyRound,
  CheckCircle2,
  Info,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

const DEMO_ACCOUNTS = [
  {
    role: 'Admin',
    username: 'admin',
    password: 'Admin@ThreatLens2026!',
    desc: 'Full administrative access, user management & all triage tools',
    color: '#0891B2',
  },
  {
    role: 'Senior Analyst',
    username: 'senior',
    password: 'Senior@ThreatLens2026!',
    desc: 'Run IOC investigations, batch triage, generate PDF reports',
    color: '#16A34A',
  },
  {
    role: 'Read-Only Analyst',
    username: 'readonly',
    password: 'Readonly@ThreatLens2026!',
    desc: 'View threat history, intelligence details & dashboard analytics',
    color: '#D97706',
  },
];

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  // Check if session expired from URL search params
  const searchParams = new URLSearchParams(location.search);
  const sessionExpired = searchParams.get('session_expired') === 'true';

  const from = location.state?.from?.pathname || '/';

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setErrorMessage('Please provide both username and password.');
      return;
    }

    setLoading(true);
    setErrorMessage('');

    try {
      await login(username.trim(), password);
      navigate(from, { replace: true });
    } catch (err) {
      const detail = err.response?.data?.detail || 'Authentication failed. Please verify your credentials.';
      setErrorMessage(detail);
    } finally {
      setLoading(false);
    }
  };

  const fillDemo = (acc) => {
    setUsername(acc.username);
    setPassword(acc.password);
    setErrorMessage('');
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        bgcolor: '#F5F7FB',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        px: 2,
        py: 6,
      }}
    >
      <Paper
        elevation={0}
        sx={{
          width: '100%',
          maxWidth: 480,
          p: 4,
          borderRadius: 3,
          border: '1px solid #DCE4EE',
          bgcolor: '#FFFFFF',
          boxShadow: '0 8px 30px rgba(15, 23, 42, 0.06)',
        }}
      >
        {/* Brand Header */}
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mb: 3 }}>
          <Box
            sx={{
              width: 52,
              height: 52,
              borderRadius: 2.5,
              bgcolor: '#0891B2',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#FFFFFF',
              boxShadow: '0 4px 14px rgba(8, 145, 178, 0.3)',
              mb: 1.5,
            }}
          >
            <ShieldCheck size={28} strokeWidth={2.4} />
          </Box>
          <Typography variant="h5" sx={{ fontWeight: 800, color: '#172B4D', letterSpacing: '-0.02em' }}>
            ThreatLens <span style={{ color: '#0891B2' }}>AI</span>
          </Typography>
          <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 600, letterSpacing: '0.08em', mt: 0.3 }}>
            CYBER THREAT INTELLIGENCE SOC
          </Typography>
        </Box>

        {sessionExpired && (
          <Alert severity="warning" icon={<Info size={18} />} sx={{ mb: 2.5, borderRadius: 2, fontSize: '0.85rem' }}>
            Your session has expired. Please sign in again to continue your investigation.
          </Alert>
        )}

        {errorMessage && (
          <Alert severity="error" sx={{ mb: 2.5, borderRadius: 2, fontSize: '0.85rem' }}>
            {errorMessage}
          </Alert>
        )}

        {/* Login Form */}
        <Box component="form" onSubmit={handleSubmit} noValidate>
          <TextField
            label="Username"
            fullWidth
            size="medium"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={loading}
            autoComplete="username"
            autoFocus
            sx={{ mb: 2 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <User size={18} color="#64748B" />
                </InputAdornment>
              ),
            }}
          />

          <TextField
            label="Password"
            type={showPassword ? 'text' : 'password'}
            fullWidth
            size="medium"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={loading}
            autoComplete="current-password"
            sx={{ mb: 3 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Lock size={18} color="#64748B" />
                </InputAdornment>
              ),
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton
                    onClick={() => setShowPassword(!showPassword)}
                    edge="end"
                    size="small"
                    sx={{ color: '#64748B' }}
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />

          <Button
            type="submit"
            fullWidth
            variant="contained"
            disabled={loading}
            sx={{
              py: 1.3,
              bgcolor: '#0891B2',
              color: '#FFFFFF',
              fontWeight: 700,
              fontSize: '0.95rem',
              borderRadius: 2,
              boxShadow: '0 2px 10px rgba(8, 145, 178, 0.25)',
              '&:hover': { bgcolor: '#0e7490' },
            }}
          >
            {loading ? (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CircularProgress size={18} color="inherit" />
                <span>Verifying Credentials...</span>
              </Box>
            ) : (
              'Authenticate & Enter SOC'
            )}
          </Button>
        </Box>

        <Divider sx={{ my: 3, borderColor: '#DCE4EE' }}>
          <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 600, px: 1 }}>
            DEMO SOC CREDENTIALS
          </Typography>
        </Divider>

        {/* Quick Demo Credentials */}
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          {DEMO_ACCOUNTS.map((acc) => (
            <Box
              key={acc.role}
              onClick={() => fillDemo(acc)}
              sx={{
                p: 1.2,
                px: 1.5,
                borderRadius: 2,
                border: '1px solid #DCE4EE',
                bgcolor: '#F8FAFC',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                transition: 'all 0.15s ease',
                '&:hover': {
                  borderColor: acc.color,
                  bgcolor: '#FFFFFF',
                  transform: 'translateY(-1px)',
                  boxShadow: '0 2px 8px rgba(15, 23, 42, 0.04)',
                },
              }}
            >
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Chip
                    label={acc.role}
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: '0.68rem',
                      fontWeight: 700,
                      bgcolor: acc.color + "15",
                      color: acc.color,
                      border: "1px solid " + acc.color + "40",
                    }}
                  />
                  <Typography variant="caption" sx={{ color: '#172B4D', fontWeight: 700, fontFamily: 'monospace' }}>
                    {acc.username}
                  </Typography>
                </Box>
                <Typography variant="caption" sx={{ color: '#64748B', fontSize: '0.7rem' }}>
                  {acc.desc}
                </Typography>
              </Box>
              <KeyRound size={15} color="#64748B" />
            </Box>
          ))}
        </Box>
      </Paper>

      <Typography variant="caption" sx={{ color: '#94A3B8', mt: 3, fontWeight: 500 }}>
        ThreatLens AI SOC • Role-Based Access Control Protected
      </Typography>
    </Box>
  );
}
