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
        return <ShieldAlert size={16} color="#DC2626" />;
      case 'medium':
        return <AlertCircle size={16} color="#D97706" />;
      case 'low':
        return <ShieldCheck size={16} color="#16A34A" />;
      default:
        return <Info size={16} color="#0891B2" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
      case 'high':
        return '#DC2626';
      case 'medium':
        return '#D97706';
      case 'low':
        return '#16A34A';
      default:
        return '#0891B2';
    }
  };

  return (
    <Card sx={{ bgcolor: '#FFFFFF', border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)', borderRadius: 2.5 }}>
      <CardContent sx={{ p: 2.8 }}>
        <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D', mb: 2 }}>
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
                  bgcolor: '#F8FAFC',
                  borderRadius: 2,
                  border: '1px solid #DCE4EE',
                  borderLeft: `4px solid ${sevColor}`,
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 1.5,
                }}
              >
                <Box sx={{ mt: 0.3 }}>{getIcon(item.severity)}</Box>
                <Box sx={{ flex: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.3 }}>
                    <Typography variant="body2" sx={{ fontWeight: 700, color: '#172B4D' }}>
                      {item.title}
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 600 }}>
                      {item.source}
                    </Typography>
                  </Box>
                  <Typography variant="caption" sx={{ color: '#64748B', display: 'block', lineHeight: 1.5 }}>
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
