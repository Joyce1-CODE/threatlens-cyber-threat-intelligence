import React from 'react';
import { Card, CardContent, Typography, Box } from '@mui/material';

export default function StatCard({ title, value, subtitle, icon: Icon, accentColor = '#00f2fe' }) {
  return (
    <Card
      sx={{
        height: '100%',
        bgcolor: '#0f172a',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        position: 'relative',
        overflow: 'hidden',
        '&:hover': {
          borderColor: 'rgba(0, 242, 254, 0.25)',
          transform: 'translateY(-2px)',
        },
      }}
    >
      <Box
        sx={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '2px',
          bgcolor: accentColor,
          opacity: 0.8,
        }}
      />
      <CardContent sx={{ p: 2.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 1.5 }}>
          <Typography variant="body2" sx={{ color: '#94a3b8', fontWeight: 600 }}>
            {title}
          </Typography>
          {Icon && (
            <Box
              sx={{
                p: 1,
                borderRadius: 1.5,
                bgcolor: `${accentColor}14`,
                color: accentColor,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Icon size={18} />
            </Box>
          )}
        </Box>
        <Typography variant="h4" sx={{ fontWeight: 800, color: '#f8fafc', mb: 0.5 }}>
          {value}
        </Typography>
        {subtitle && (
          <Typography variant="caption" sx={{ color: '#64748b', display: 'block' }}>
            {subtitle}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}
