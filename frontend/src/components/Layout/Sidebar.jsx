import React, { useEffect, useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { Box, Typography, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Divider } from '@mui/material';
import { LayoutDashboard, Search, Layers, History, Settings, ShieldCheck, Activity, Users } from 'lucide-react';
import { threatApi } from '../../api/client';
import ProviderStatusBadge from '../Common/ProviderStatusBadge';
import { useAuth } from '../../contexts/AuthContext';

export default function Sidebar({ width = 260 }) {
  const location = useLocation();
  const { user, isAdmin } = useAuth();
  const [providers, setProviders] = useState(null);

  useEffect(() => {
    // Only attempt fetch if user is authenticated to avoid 401s during transitions
    if (user) {
      threatApi.getProviderStatus()
        .then(data => setProviders(data.providers))
        .catch(() => {});
    }
  }, [location.pathname, user]);

  const navItems = [
    { label: 'Overview', path: '/', icon: LayoutDashboard },
    { label: 'Investigate', path: '/investigate', icon: Search },
    { label: 'Bulk Triage', path: '/bulk', icon: Layers },
    { label: 'History', path: '/history', icon: History },
    ...(isAdmin ? [{ label: 'User Accounts', path: '/users', icon: Users }] : []),
    { label: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <Box
      sx={{
        width,
        height: '100vh',
        bgcolor: '#EDF2F8',
        borderRight: '1px solid #DCE4EE',
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
            bgcolor: '#0891B2',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#FFFFFF',
            boxShadow: '0 2px 8px rgba(8, 145, 178, 0.25)',
          }}
        >
          <ShieldCheck size={22} strokeWidth={2.4} />
        </Box>
        <Box>
          <Typography variant="subtitle1" sx={{ fontWeight: 800, color: '#172B4D', lineHeight: 1.2 }}>
            ThreatLens <span style={{ color: '#0891B2' }}>AI</span>
          </Typography>
          <Typography variant="caption" sx={{ color: '#64748B', fontSize: '0.7rem', fontWeight: 600 }}>
            CYBER THREAT INTEL
          </Typography>
        </Box>
      </Box>

      <Divider sx={{ borderColor: '#DCE4EE' }} />

      {/* Navigation Links */}
      <Box sx={{ flex: 1, py: 2 }}>
        <Typography
          variant="caption"
          sx={{ px: 3, mb: 1, display: 'block', color: '#64748B', fontWeight: 700, letterSpacing: '0.05em' }}
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
                    bgcolor: isActive ? 'rgba(8, 145, 178, 0.1)' : 'transparent',
                    border: isActive ? '1px solid rgba(8, 145, 178, 0.3)' : '1px solid transparent',
                    color: isActive ? '#0891B2' : '#64748B',
                    '&:hover': {
                      bgcolor: isActive ? 'rgba(8, 145, 178, 0.14)' : '#E2E8F0',
                      color: isActive ? '#0891B2' : '#172B4D',
                    },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 36, color: isActive ? '#0891B2' : '#64748B' }}>
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
      <Box sx={{ p: 2, m: 1.5, bgcolor: '#FFFFFF', borderRadius: 2, border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.2 }}>
          <Activity size={15} color="#0891B2" />
          <Typography variant="caption" sx={{ color: '#172B4D', fontWeight: 700 }}>
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
