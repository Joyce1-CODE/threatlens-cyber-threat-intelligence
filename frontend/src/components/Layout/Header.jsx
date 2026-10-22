import React from 'react';
import { Box, Typography, Button } from '@mui/material';
import { Search, Terminal, ExternalLink } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function Header({ sidebarWidth = 260 }) {
  const navigate = useNavigate();

  return (
    <Box
      sx={{
        height: 64,
        bgcolor: 'rgba(8, 12, 20, 0.85)',
        backdropFilter: 'blur(12px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        px: 3.5,
        position: 'sticky',
        top: 0,
        zIndex: 1100,
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        <Box
          sx={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 1,
            px: 1.5,
            py: 0.4,
            borderRadius: 1.5,
            bgcolor: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
          }}
        >
          <Box
            component="span"
            sx={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              bgcolor: '#10b981',
              boxShadow: '0 0 6px #10b981',
            }}
          />
          <Typography variant="caption" sx={{ color: '#10b981', fontWeight: 700, fontSize: '0.72rem' }}>
            SOC LIVE TELEMETRY
          </Typography>
        </Box>
      </Box>

      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Button
          variant="outlined"
          size="small"
          startIcon={<Search size={14} />}
          onClick={() => navigate('/investigate')}
          sx={{
            borderColor: 'rgba(0, 242, 254, 0.3)',
            color: '#00f2fe',
            fontSize: '0.8rem',
            '&:hover': {
              borderColor: '#00f2fe',
              bgcolor: 'rgba(0, 242, 254, 0.08)',
            },
          }}
        >
          Quick Scan
        </Button>
        <Button
          variant="text"
          size="small"
          startIcon={<Terminal size={14} />}
          onClick={() => navigate('/settings')}
          sx={{
            color: '#94a3b8',
            fontSize: '0.8rem',
            '&:hover': { color: '#f8fafc' },
          }}
        >
          API Setup
        </Button>
      </Box>
    </Box>
  );
}
