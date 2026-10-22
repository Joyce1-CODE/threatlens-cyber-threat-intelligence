import React from 'react';
import { Card, CardContent, Typography, Box, List, ListItem, ListItemIcon, ListItemText } from '@mui/material';
import { ShieldCheck, CheckCircle2 } from 'lucide-react';

export default function RecommendationsCard({ recommendations = [], severity = 'Low' }) {
  if (!recommendations || recommendations.length === 0) return null;

  const isHighRisk = severity === 'Critical' || severity === 'High';

  return (
    <Card
      sx={{
        bgcolor: '#0f172a',
        border: '1px solid rgba(255, 255, 255, 0.08)',
      }}
    >
      <CardContent sx={{ p: 2.8 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.2, mb: 2 }}>
          <ShieldCheck size={20} color={isHighRisk ? '#f97316' : '#10b981'} />
          <Typography variant="h6" sx={{ fontWeight: 700, color: '#f8fafc' }}>
            Actionable Mitigation Guidance
          </Typography>
        </Box>

        <List disablePadding>
          {recommendations.map((rec, idx) => (
            <ListItem
              key={idx}
              disableGutters
              sx={{
                py: 1,
                alignItems: 'flex-start',
                borderBottom: idx < recommendations.length - 1 ? '1px solid rgba(255, 255, 255, 0.04)' : 'none',
              }}
            >
              <ListItemIcon sx={{ minWidth: 28, mt: 0.4, color: isHighRisk ? '#f97316' : '#10b981' }}>
                <CheckCircle2 size={16} />
              </ListItemIcon>
              <ListItemText
                primary={rec}
                primaryTypographyProps={{
                  variant: 'body2',
                  sx: { color: '#cbd5e1', lineHeight: 1.5, fontWeight: 500 },
                }}
              />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
}
