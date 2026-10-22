import React from 'react';
import { Box, Typography } from '@mui/material';
import { CheckCircle2, AlertTriangle, XCircle, HelpCircle } from 'lucide-react';

export default function ProviderStatusBadge({ name, configured, status }) {
  const isReady = configured && status === 'ready';
  const isMissing = status === 'missing_key' || !configured;
  const isRateLimited = status === 'rate_limited';

  let color = '#10b981';
  let Icon = CheckCircle2;
  let text = 'Ready';

  if (isMissing) {
    color = '#f59e0b';
    Icon = AlertTriangle;
    text = 'Key Missing';
  } else if (isRateLimited) {
    color = '#f97316';
    Icon = AlertTriangle;
    text = 'Rate Limited';
  } else if (status === 'error' || status === 'unauthorized') {
    color = '#ef4444';
    Icon = XCircle;
    text = 'Auth Error';
  }

  return (
    <Box
      sx={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 0.8,
        px: 1.2,
        py: 0.5,
        borderRadius: 1.5,
        bgcolor: `${color}14`,
        border: `1px solid ${color}33`,
      }}
    >
      <Icon size={14} color={color} />
      <Typography variant="caption" sx={{ color: '#f1f5f9', fontWeight: 600 }}>
        {name}:
      </Typography>
      <Typography variant="caption" sx={{ color, fontWeight: 700 }}>
        {text}
      </Typography>
    </Box>
  );
}
