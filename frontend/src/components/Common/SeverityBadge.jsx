import React from 'react';
import { Chip, Box } from '@mui/material';

const severityConfig = {
  Low: {
    color: '#10b981',
    bg: 'rgba(16, 185, 129, 0.12)',
    border: 'rgba(16, 185, 129, 0.35)',
    label: 'Low Risk',
  },
  Medium: {
    color: '#f59e0b',
    bg: 'rgba(245, 158, 11, 0.12)',
    border: 'rgba(245, 158, 11, 0.35)',
    label: 'Medium Risk',
  },
  High: {
    color: '#f97316',
    bg: 'rgba(249, 115, 22, 0.12)',
    border: 'rgba(249, 115, 22, 0.35)',
    label: 'High Risk',
  },
  Critical: {
    color: '#ef4444',
    bg: 'rgba(239, 68, 68, 0.16)',
    border: 'rgba(239, 68, 68, 0.45)',
    label: 'Critical Risk',
  },
};

export default function SeverityBadge({ severity = 'Low', size = 'small', showDot = true }) {
  const normSev = severity ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase() : 'Low';
  const cfg = severityConfig[normSev] || severityConfig.Low;

  return (
    <Chip
      size={size}
      icon={
        showDot ? (
          <Box
            component="span"
            sx={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              bgcolor: cfg.color,
              boxShadow: `0 0 6px ${cfg.color}`,
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
