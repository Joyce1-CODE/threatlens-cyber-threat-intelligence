import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, CssBaseline } from '@mui/material';
import { cyberTheme } from './theme';

import AppLayout from './components/Layout/AppLayout';
import Dashboard from './pages/Dashboard';
import Investigate from './pages/Investigate';
import History from './pages/History';
import InvestigationDetail from './pages/InvestigationDetail';
import Settings from './pages/Settings';

export default function App() {
  return (
    <ThemeProvider theme={cyberTheme}>
      <CssBaseline />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<AppLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="investigate" element={<Investigate />} />
            <Route path="history" element={<History />} />
            <Route path="investigation/:id" element={<InvestigationDetail />} />
            <Route path="settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  );
}
