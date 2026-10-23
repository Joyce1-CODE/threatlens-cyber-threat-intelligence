import React from 'react';
import { Box, Typography, CircularProgress } from '@mui/material';
import SeverityBadge from './SeverityBadge';

export default function RiskScoreMeter({ score = 0, severity = 'Low', confidence = 'Low' }) {
  let color = '#16A34A';
  if (severity === 'Unknown' || severity === 'Unverified' || confidence === 'None') {
    color = '#64748B';
  } else if (score >= 75) {
    color = '#DC2626';
  } else if (score >= 50) {
    color = '#EA580C';
  } else if (score >= 20) {
    color = '#D97706';
  }

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        p: 2.8,
        bgcolor: '#FFFFFF',
        border: '1px solid #DCE4EE',
        borderRadius: 2.5,
        boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)',
        position: 'relative',
        minWidth: 200,
        height: '100%',
      }}
    >
      <Box sx={{ position: 'relative', display: 'inline-flex', my: 1 }}>
        {/* Background Track */}
        <CircularProgress
          variant="determinate"
          value={100}
          size={120}
          thickness={5}
          sx={{ color: '#E2E8F0' }}
        />
        {/* Actual Value Progress */}
        <CircularProgress
          variant="determinate"
          value={score}
          size={120}
          thickness={5}
          sx={{
            color: color,
            position: 'absolute',
            left: 0,
            strokeLinecap: 'round',
          }}
        />
        <Box
          sx={{
            top: 0,
            left: 0,
            bottom: 0,
            right: 0,
            position: 'absolute',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Typography
            variant="h4"
            component="div"
            sx={{ fontWeight: 800, color: '#172B4D', lineHeight: 1 }}
          >
            {score}
          </Typography>
          <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 600, mt: 0.3 }}>
            / 100
          </Typography>
        </Box>
      </Box>

      <Box sx={{ mt: 1.5, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0.8 }}>
        <SeverityBadge severity={severity} size="medium" />
        <Typography variant="caption" sx={{ color: '#64748B', fontSize: '0.75rem' }}>
          Confidence: <strong style={{ color: '#172B4D' }}>{confidence}</strong>
        </Typography>
      </Box>
    </Box>
  );
}
