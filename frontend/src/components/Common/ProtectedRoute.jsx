import React from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { Box, Typography, Button, Paper, CircularProgress } from '@mui/material';
import { ShieldAlert, ArrowLeft } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';

export default function ProtectedRoute({ children, allowedRoles }) {
  const { user, loading, isAuthenticated } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  if (loading) {
    return (
      <Box
        sx={{
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          bgcolor: '#F5F7FB',
          gap: 2,
        }}
      >
        <CircularProgress size={38} sx={{ color: '#0891B2' }} />
        <Typography variant="body2" sx={{ color: '#64748B', fontWeight: 600 }}>
          Authenticating ThreatLens AI Session...
        </Typography>
      </Box>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user?.role)) {
    return (
      <Box
        sx={{
          p: 6,
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '80vh',
        }}
      >
        <Paper
          elevation={0}
          sx={{
            p: 5,
            maxWidth: 520,
            textAlign: 'center',
            borderRadius: 3,
            border: '1px solid #DCE4EE',
            bgcolor: '#FFFFFF',
            boxShadow: '0 4px 20px rgba(15, 23, 42, 0.05)',
          }}
        >
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: '50%',
              bgcolor: 'rgba(234, 88, 12, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 20px',
              color: '#EA580C',
            }}
          >
            <ShieldAlert size={30} strokeWidth={2.2} />
          </Box>
          <Typography variant="h6" sx={{ fontWeight: 800, color: '#172B4D', mb: 1 }}>
            Access Restricted (403 Forbidden)
          </Typography>
          <Typography variant="body2" sx={{ color: '#64748B', mb: 3, lineHeight: 1.6 }}>
            Your account is assigned the <strong>{user?.role}</strong> role. This section requires elevated administrative permissions.
          </Typography>
          <Button
            variant="contained"
            startIcon={<ArrowLeft size={16} />}
            onClick={() => navigate('/')}
            sx={{
              bgcolor: '#0891B2',
              color: '#FFFFFF',
              fontWeight: 700,
              px: 3,
              py: 1,
              '&:hover': { bgcolor: '#0e7490' },
            }}
          >
            Return to Dashboard
          </Button>
        </Paper>
      </Box>
    );
  }

  return children;
}
