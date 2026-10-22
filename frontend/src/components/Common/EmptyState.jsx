import React from 'react';
import { Box, Typography, Button } from '@mui/material';
import { ShieldAlert, Search } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function EmptyState({
  title = "No Investigations Recorded",
  description = "Start by submitting an IP, domain, URL, or hash for passive threat intelligence evaluation.",
  actionText = "Investigate an IOC",
  actionLink = "/investigate"
}) {
  const navigate = useNavigate();

  return (
    <Box
      sx={{
        py: 6,
        px: 3,
        textAlign: 'center',
        bgcolor: 'rgba(15, 23, 42, 0.4)',
        border: '1px dashed rgba(255, 255, 255, 0.12)',
        borderRadius: 3,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <Box
        sx={{
          width: 56,
          height: 56,
          borderRadius: '50%',
          bgcolor: 'rgba(0, 242, 254, 0.08)',
          border: '1px solid rgba(0, 242, 254, 0.2)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#00f2fe',
          mb: 2,
        }}
      >
        <Search size={26} />
      </Box>
      <Typography variant="h6" sx={{ fontWeight: 600, color: '#f8fafc', mb: 0.8 }}>
        {title}
      </Typography>
      <Typography variant="body2" sx={{ color: '#94a3b8', maxWidth: 440, mb: 2.5 }}>
        {description}
      </Typography>
      {actionText && (
        <Button
          variant="contained"
          onClick={() => navigate(actionLink)}
          sx={{ px: 3, py: 1 }}
        >
          {actionText}
        </Button>
      )}
    </Box>
  );
}
