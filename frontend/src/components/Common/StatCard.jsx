import React from 'react';
import { Card, CardContent, Typography, Box } from '@mui/material';

export default function StatCard({ title, value, subtitle, icon: Icon, accentColor = '#0891B2' }) {
  return (
    <Card
      sx={{
        height: '100%',
        bgcolor: '#FFFFFF',
        border: '1px solid #DCE4EE',
        borderRadius: 2.5,
        boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)',
        position: 'relative',
        overflow: 'hidden',
        transition: 'all 0.2s ease',
        '&:hover': {
          borderColor: '#CBD5E1',
          boxShadow: '0 4px 12px rgba(15, 23, 42, 0.07)',
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
          height: '3px',
          bgcolor: accentColor,
        }}
      />
      <CardContent sx={{ p: 2.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 1.5 }}>
          <Typography variant="body2" sx={{ color: '#64748B', fontWeight: 600 }}>
            {title}
          </Typography>
          {Icon && (
            <Box
              sx={{
                p: 0.9,
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
        <Typography variant="h4" sx={{ fontWeight: 800, color: '#172B4D', mb: 0.5 }}>
          {value}
        </Typography>
        {subtitle && (
          <Typography variant="caption" sx={{ color: '#64748B', display: 'block', fontWeight: 500 }}>
            {subtitle}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}
