import React from 'react';
import { Card, CardContent, Typography, Box, List, ListItem, ListItemIcon, ListItemText } from '@mui/material';
import { ShieldCheck, CheckCircle2 } from 'lucide-react';

export default function RecommendationsCard({ recommendations = [], severity = 'Low' }) {
  if (!recommendations || recommendations.length === 0) return null;

  const isHighRisk = severity === 'Critical' || severity === 'High';
  const accentColor = isHighRisk ? '#EA580C' : '#16A34A';

  return (
    <Card
      sx={{
        bgcolor: '#FFFFFF',
        border: '1px solid #DCE4EE',
        boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)',
        borderRadius: 2.5,
      }}
    >
      <CardContent sx={{ p: 2.8 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.2, mb: 2 }}>
          <ShieldCheck size={20} color={accentColor} />
          <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D' }}>
            Actionable Mitigation Guidance
          </Typography>
        </Box>

        <List disablePadding>
          {recommendations.map((rec, idx) => (
            <ListItem
              key={idx}
              disableGutters
              sx={{
                py: 1.2,
                alignItems: 'flex-start',
                borderBottom: idx < recommendations.length - 1 ? '1px solid #DCE4EE' : 'none',
              }}
            >
              <ListItemIcon sx={{ minWidth: 28, mt: 0.4, color: accentColor }}>
                <CheckCircle2 size={16} />
              </ListItemIcon>
              <ListItemText
                primary={rec}
                primaryTypographyProps={{
                  variant: 'body2',
                  sx: { color: '#172B4D', lineHeight: 1.5, fontWeight: 500 },
                }}
              />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
}
