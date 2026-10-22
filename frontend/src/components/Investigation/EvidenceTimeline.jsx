import React from 'react';
import { Card, CardContent, Typography, Box } from '@mui/material';
import { ShieldCheck, AlertCircle, Info, ShieldAlert } from 'lucide-react';

export default function EvidenceTimeline({ evidence = [] }) {
  if (!evidence || evidence.length === 0) {
    return null;
  }

  const getIcon = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
      case 'high':
        return <ShieldAlert size={16} color="#ef4444" />;
      case 'medium':
        return <AlertCircle size={16} color="#f59e0b" />;
      case 'low':
        return <ShieldCheck size={16} color="#10b981" />;
      default:
        return <Info size={16} color="#38bdf8" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
      case 'high':
        return '#ef4444';
      case 'medium':
        return '#f59e0b';
      case 'low':
        return '#10b981';
      default:
        return '#38bdf8';
    }
  };

  return (
    <Card sx={{ bgcolor: '#0f172a', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
      <CardContent sx={{ p: 2.8 }}>
        <Typography variant="h6" sx={{ fontWeight: 700, color: '#f8fafc', mb: 2 }}>
          Evidence & Corroborating Signals ({evidence.length})
        </Typography>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          {evidence.map((item, idx) => {
            const sevColor = getSeverityColor(item.severity);
            return (
              <Box
                key={idx}
                sx={{
                  p: 1.8,
                  bgcolor: '#080c14',
                  borderRadius: 2,
                  borderLeft: `4px solid ${sevColor}`,
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 1.5,
                }}
              >
                <Box sx={{ mt: 0.3 }}>{getIcon(item.severity)}</Box>
                <Box sx={{ flex: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.3 }}>
                    <Typography variant="body2" sx={{ fontWeight: 700, color: '#f1f5f9' }}>
                      {item.title}
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 600 }}>
                      {item.source}
                    </Typography>
                  </Box>
                  <Typography variant="caption" sx={{ color: '#94a3b8', display: 'block', lineHeight: 1.5 }}>
                    {item.description}
                  </Typography>
                </Box>
              </Box>
            );
          })}
        </Box>
      </CardContent>
    </Card>
  );
}
