import React from 'react';
import { Box, Typography } from '@mui/material';
import { CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';

export default function ProviderStatusBadge({ name, configured, status }) {
  const isReady = configured && status === 'ready';
  const isMissing = status === 'missing_key' || !configured;
  const isRateLimited = status === 'rate_limited';

  let color = '#16A34A';
  let Icon = CheckCircle2;
  let text = 'Ready';

  if (isMissing) {
    color = '#D97706';
    Icon = AlertTriangle;
    text = 'Key Missing';
  } else if (isRateLimited) {
    color = '#EA580C';
    Icon = AlertTriangle;
    text = 'Rate Limited';
  } else if (status === 'error' || status === 'unauthorized') {
    color = '#DC2626';
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
        bgcolor: `${color}12`,
        border: `1px solid ${color}33`,
      }}
    >
      <Icon size={14} color={color} />
      <Typography variant="caption" sx={{ color: '#172B4D', fontWeight: 600 }}>
        {name}:
      </Typography>
      <Typography variant="caption" sx={{ color, fontWeight: 700 }}>
        {text}
      </Typography>
    </Box>
  );
}
