import React, { useEffect, useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { Box, Typography, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Divider } from '@mui/material';
import { LayoutDashboard, Search, Layers, History, Settings, ShieldCheck, Activity } from 'lucide-react';
import { threatApi } from '../../api/client';
import ProviderStatusBadge from '../Common/ProviderStatusBadge';

const navItems = [
  { label: 'Overview', path: '/', icon: LayoutDashboard },
  { label: 'Investigate', path: '/investigate', icon: Search },
  { label: 'Bulk Triage', path: '/bulk', icon: Layers },
  { label: 'History', path: '/history', icon: History },
  { label: 'Settings', path: '/settings', icon: Settings },
];

export default function Sidebar({ width = 260 }) {
  const location = useLocation();
  const [providers, setProviders] = useState(null);

  useEffect(() => {
    threatApi.getProviderStatus()
      .then(data => setProviders(data.providers))
      .catch(() => {});
  }, [location.pathname]);

  return (
    <Box
      sx={{
        width,
        height: '100vh',
        bgcolor: '#090e1a',
        borderRight: '1px solid rgba(255, 255, 255, 0.08)',
        display: 'flex',
        flexDirection: 'column',
        position: 'fixed',
        left: 0,
        top: 0,
        zIndex: 1200,
      }}
    >
      {/* Brand Header */}
      <Box sx={{ p: 2.8, display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Box
          sx={{
            width: 38,
            height: 38,
            borderRadius: 2,
            background: 'linear-gradient(135deg, #00f2fe 0%, #0284c7 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#080c14',
            boxShadow: '0 0 15px rgba(0, 242, 254, 0.4)',
          }}
        >
          <ShieldCheck size={22} strokeWidth={2.5} />
        </Box>
        <Box>
          <Typography variant="subtitle1" sx={{ fontWeight: 800, color: '#f8fafc', lineHeight: 1.2 }}>
            ThreatLens <span style={{ color: '#00f2fe' }}>AI</span>
          </Typography>
          <Typography variant="caption" sx={{ color: '#64748b', fontSize: '0.7rem', fontWeight: 600 }}>
            CYBER THREAT INTEL
          </Typography>
        </Box>
      </Box>

      <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.06)' }} />

      {/* Navigation Links */}
      <Box sx={{ flex: 1, py: 2 }}>
        <Typography
          variant="caption"
          sx={{ px: 3, mb: 1, display: 'block', color: '#475569', fontWeight: 700, letterSpacing: '0.05em' }}
        >
          NAVIGATION
        </Typography>
        <List sx={{ px: 1.5 }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path ||
              (item.path !== '/' && location.pathname.startsWith(item.path));

            return (
              <ListItem key={item.path} disablePadding sx={{ mb: 0.5 }}>
                <ListItemButton
                  component={NavLink}
                  to={item.path}
                  sx={{
                    borderRadius: 2,
                    py: 1,
                    px: 1.8,
                    bgcolor: isActive ? 'rgba(0, 242, 254, 0.08)' : 'transparent',
                    border: isActive ? '1px solid rgba(0, 242, 254, 0.25)' : '1px solid transparent',
                    color: isActive ? '#00f2fe' : '#94a3b8',
                    '&:hover': {
                      bgcolor: 'rgba(255, 255, 255, 0.04)',
                      color: '#f8fafc',
                    },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 36, color: isActive ? '#00f2fe' : '#64748b' }}>
                    <Icon size={18} />
                  </ListItemIcon>
                  <ListItemText
                    primary={item.label}
                    primaryTypographyProps={{
                      fontWeight: isActive ? 700 : 500,
                      fontSize: '0.9rem',
                    }}
                  />
                </ListItemButton>
              </ListItem>
            );
          })}
        </List>
      </Box>

      {/* Intelligence Source Status Footer */}
      <Box sx={{ p: 2, m: 1.5, bgcolor: 'rgba(15, 23, 42, 0.6)', borderRadius: 2, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.2 }}>
          <Activity size={14} color="#00f2fe" />
          <Typography variant="caption" sx={{ color: '#94a3b8', fontWeight: 700 }}>
            INTELLIGENCE FEEDS
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.8 }}>
          <ProviderStatusBadge
            name="VirusTotal v3"
            configured={providers?.virustotal?.configured}
            status={providers?.virustotal?.status}
          />
          <ProviderStatusBadge
            name="AlienVault OTX"
            configured={providers?.alienvault_otx?.configured}
            status={providers?.alienvault_otx?.status}
          />
        </Box>
      </Box>
    </Box>
  );
}
