import React from 'react';
import { Outlet } from 'react-router-dom';
import { Box } from '@mui/material';
import Sidebar from './Sidebar';
import Header from './Header';

const SIDEBAR_WIDTH = 260;

export default function AppLayout() {
  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: '#080c14' }}>
      <Sidebar width={SIDEBAR_WIDTH} />
      <Box
        sx={{
          flex: 1,
          ml: `${SIDEBAR_WIDTH}px`,
          display: 'flex',
          flexDirection: 'column',
          minWidth: 0,
        }}
      >
        <Header sidebarWidth={SIDEBAR_WIDTH} />
        <Box
          component="main"
          sx={{
            flex: 1,
            p: { xs: 2.5, md: 3.5 },
            maxWidth: 1400,
            width: '100%',
            mx: 'auto',
          }}
        >
          <Outlet />
        </Box>
      </Box>
    </Box>
  );
}
