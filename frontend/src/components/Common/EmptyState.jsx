import React from 'react';
import { Box, Typography, Button } from '@mui/material';
import { Search } from 'lucide-react';
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
        bgcolor: '#FFFFFF',
        border: '1px dashed #DCE4EE',
        borderRadius: 2.5,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <Box
        sx={{
          width: 54,
          height: 54,
          borderRadius: '50%',
          bgcolor: 'rgba(8, 145, 178, 0.08)',
          border: '1px solid rgba(8, 145, 178, 0.25)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#0891B2',
          mb: 2,
        }}
      >
        <Search size={24} />
      </Box>
      <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D', mb: 0.8 }}>
        {title}
      </Typography>
      <Typography variant="body2" sx={{ color: '#64748B', maxWidth: 460, mb: 2.5 }}>
        {description}
      </Typography>
      {actionText && (
        <Button
          variant="contained"
          onClick={() => navigate(actionLink)}
          sx={{
            bgcolor: '#0891B2',
            color: '#FFFFFF',
            px: 3,
            py: 1,
            '&:hover': { bgcolor: '#0E7490' },
          }}
        >
          {actionText}
        </Button>
      )}
    </Box>
  );
}
