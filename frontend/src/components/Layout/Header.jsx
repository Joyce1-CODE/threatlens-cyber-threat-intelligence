import React, { useState } from 'react';
import {
  Box,
  Typography,
  Button,
  Chip,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Tooltip,
} from '@mui/material';
import { Search, Terminal, LogOut, User, ShieldCheck } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

const ROLE_CHIPS = {
  Admin: { bg: 'rgba(8, 145, 178, 0.1)', color: '#0891B2', border: 'rgba(8, 145, 178, 0.3)' },
  'Senior Analyst': { bg: 'rgba(22, 163, 74, 0.1)', color: '#16A34A', border: 'rgba(22, 163, 74, 0.3)' },
  'Read-Only Analyst': { bg: 'rgba(217, 119, 6, 0.1)', color: '#D97706', border: 'rgba(217, 119, 6, 0.3)' },
};

export default function Header({ sidebarWidth = 260 }) {
  const navigate = useNavigate();
  const { user, logout, isReadOnly } = useAuth();
  const [anchorEl, setAnchorEl] = useState(null);

  const handleOpenMenu = (e) => setAnchorEl(e.currentTarget);
  const handleCloseMenu = () => setAnchorEl(null);

  const handleLogout = async () => {
    handleCloseMenu();
    await logout();
    navigate('/login');
  };

  const roleStyle = (user && ROLE_CHIPS[user.role]) || ROLE_CHIPS['Read-Only Analyst'];

  return (
    <Box
      sx={{
        height: 64,
        bgcolor: 'rgba(255, 255, 255, 0.95)',
        backdropFilter: 'blur(8px)',
        borderBottom: '1px solid #DCE4EE',
        boxShadow: '0 1px 2px rgba(15, 23, 42, 0.03)',
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
            py: 0.45,
            borderRadius: 1.5,
            bgcolor: 'rgba(22, 163, 74, 0.08)',
            border: '1px solid rgba(22, 163, 74, 0.25)',
          }}
        >
          <Box
            component="span"
            sx={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              bgcolor: '#16A34A',
            }}
          />
          <Typography
            variant="caption"
            sx={{ color: '#16A34A', fontWeight: 700, fontSize: '0.72rem', letterSpacing: '0.04em' }}
          >
            SOC LIVE TELEMETRY
          </Typography>
        </Box>
      </Box>

      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.8 }}>
        <Tooltip title={isReadOnly ? 'Investigation creation is restricted for Read-Only Analysts' : 'Investigate IOC'}>
          <span>
            <Button
              variant="outlined"
              size="small"
              disabled={isReadOnly}
              startIcon={<Search size={14} />}
              onClick={() => navigate('/investigate')}
              sx={{
                borderColor: 'rgba(8, 145, 178, 0.4)',
                color: '#0891B2',
                fontSize: '0.8rem',
                fontWeight: 600,
                '&:hover': {
                  borderColor: '#0891B2',
                  bgcolor: 'rgba(8, 145, 178, 0.06)',
                },
              }}
            >
              Quick Scan
            </Button>
          </span>
        </Tooltip>

        <Button
          variant="text"
          size="small"
          startIcon={<Terminal size={14} />}
          onClick={() => navigate('/settings')}
          sx={{
            color: '#64748B',
            fontSize: '0.8rem',
            fontWeight: 600,
            '&:hover': {
              color: '#172B4D',
              bgcolor: 'rgba(15, 23, 42, 0.04)',
            },
          }}
        >
          API Setup
        </Button>

        <Divider orientation="vertical" flexItem sx={{ my: 1.5, borderColor: '#DCE4EE' }} />

        {/* User Profile Pill */}
        {user && (
          <>
            <Box
              onClick={handleOpenMenu}
              sx={{
                display: 'flex',
                alignItems: 'center',
                gap: 1.2,
                px: 1.2,
                py: 0.6,
                borderRadius: 2,
                cursor: 'pointer',
                border: '1px solid #DCE4EE',
                bgcolor: '#F8FAFC',
                transition: 'all 0.15s ease',
                '&:hover': {
                  bgcolor: '#FFFFFF',
                  borderColor: '#0891B2',
                  boxShadow: '0 2px 8px rgba(15, 23, 42, 0.04)',
                },
              }}
            >
              <Box
                sx={{
                  width: 28,
                  height: 28,
                  borderRadius: '50%',
                  bgcolor: '#0891B2',
                  color: '#FFFFFF',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontWeight: 700,
                  fontSize: '0.75rem',
                }}
              >
                {(user.full_name || user.username)[0].toUpperCase()}
              </Box>
              <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
                <Typography variant="caption" sx={{ fontWeight: 700, color: '#172B4D', lineHeight: 1.1 }}>
                  {user.username}
                </Typography>
                <Chip
                  label={user.role}
                  size="small"
                  sx={{
                    height: 16,
                    fontSize: '0.62rem',
                    fontWeight: 700,
                    bgcolor: roleStyle.bg,
                    color: roleStyle.color,
                    border: '1px solid ' + roleStyle.border,
                    px: 0,
                  }}
                />
              </Box>
            </Box>

            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={handleCloseMenu}
              slotProps={{
                paper: {
                  elevation: 0,
                  sx: {
                    mt: 1,
                    minWidth: 200,
                    borderRadius: 2,
                    border: "1px solid #DCE4EE",
                    boxShadow: "0 4px 20px rgba(15, 23, 42, 0.08)",
                  },
                },
              }}
              transformOrigin={{ horizontal: 'right', vertical: 'top' }}
              anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
            >
              <Box sx={{ px: 2, py: 1.2 }}>
                <Typography variant="body2" sx={{ fontWeight: 700, color: '#172B4D' }}>
                  {user.full_name || user.username}
                </Typography>
                <Typography variant="caption" sx={{ color: '#64748B' }}>
                  {user.email}
                </Typography>
              </Box>
              <Divider sx={{ borderColor: '#DCE4EE' }} />
              <MenuItem onClick={handleLogout} sx={{ color: '#EF4444', py: 1 }}>
                <ListItemIcon sx={{ color: '#EF4444', minWidth: 30 }}>
                  <LogOut size={16} />
                </ListItemIcon>
                <ListItemText primary="Sign Out" primaryTypographyProps={{ fontSize: '0.85rem', fontWeight: 600 }} />
              </MenuItem>
            </Menu>
          </>
        )}
      </Box>
    </Box>
  );
}
