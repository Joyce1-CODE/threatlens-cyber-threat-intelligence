import React from 'react';
import { Box, Typography, CircularProgress } from '@mui/material';
import SeverityBadge from './SeverityBadge';

export default function RiskScoreMeter({ score = 0, severity = 'Low', confidence = 'Low' }) {
  let color = '#10b981';
  if (score >= 75) color = '#ef4444';
  else if (score >= 50) color = '#f97316';
  else if (score >= 20) color = '#f59e0b';

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        p: 2.5,
        bgcolor: '#0c1322',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 3,
        position: 'relative',
        minWidth: 200,
      }}
    >
      <Box sx={{ position: 'relative', display: 'inline-flex', my: 1 }}>
        {/* Background Track */}
        <CircularProgress
          variant="determinate"
          value={100}
          size={120}
          thickness={5}
          sx={{ color: 'rgba(255, 255, 255, 0.06)' }}
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
            filter: `drop-shadow(0 0 8px ${color}88)`,
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
            sx={{ fontWeight: 800, color: '#f8fafc', lineHeight: 1 }}
          >
            {score}
          </Typography>
          <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 600, mt: 0.3 }}>
            / 100
          </Typography>
        </Box>
      </Box>

      <Box sx={{ mt: 1.5, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0.8 }}>
        <SeverityBadge severity={severity} size="medium" />
        <Typography variant="caption" sx={{ color: '#94a3b8', fontSize: '0.75rem' }}>
          Confidence: <strong style={{ color: '#f1f5f9' }}>{confidence}</strong>
        </Typography>
      </Box>
    </Box>
  );
}
