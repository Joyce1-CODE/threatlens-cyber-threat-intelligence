import React from 'react';
import { Chip, Box } from '@mui/material';

const severityConfig = {
  Low: {
    color: '#16A34A',
    bg: 'rgba(22, 163, 74, 0.08)',
    border: 'rgba(22, 163, 74, 0.25)',
    label: 'Low Risk',
  },
  Medium: {
    color: '#D97706',
    bg: 'rgba(217, 119, 6, 0.08)',
    border: 'rgba(217, 119, 6, 0.25)',
    label: 'Medium Risk',
  },
  High: {
    color: '#EA580C',
    bg: 'rgba(234, 88, 12, 0.08)',
    border: 'rgba(234, 88, 12, 0.25)',
    label: 'High Risk',
  },
  Critical: {
    color: '#DC2626',
    bg: 'rgba(220, 38, 38, 0.08)',
    border: 'rgba(220, 38, 38, 0.25)',
    label: 'Critical Risk',
  },
  Unknown: {
    color: '#64748B',
    bg: 'rgba(100, 116, 139, 0.08)',
    border: 'rgba(100, 116, 139, 0.25)',
    label: 'Unverified',
  },
  Unverified: {
    color: '#64748B',
    bg: 'rgba(100, 116, 139, 0.08)',
    border: 'rgba(100, 116, 139, 0.25)',
    label: 'Unverified',
  },
};

export default function SeverityBadge({ severity = 'Low', size = 'small', showDot = true }) {
  const normSev = severity ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase() : 'Low';
  const cfg = severityConfig[normSev] || severityConfig[severity] || severityConfig.Low;

  return (
    <Chip
      size={size}
      icon={
        showDot ? (
          <Box
            component="span"
            sx={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              bgcolor: cfg.color,
              ml: 1,
            }}
          />
        ) : undefined
      }
      label={cfg.label}
      sx={{
        bgcolor: cfg.bg,
        color: cfg.color,
        border: `1px solid ${cfg.border}`,
        fontWeight: 600,
        fontSize: size === 'small' ? '0.75rem' : '0.85rem',
      }}
    />
  );
}
