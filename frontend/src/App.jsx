import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, CssBaseline } from '@mui/material';
import { cyberTheme } from './theme';

import { AuthProvider } from './contexts/AuthContext';
import ProtectedRoute from './components/Common/ProtectedRoute';
import AppLayout from './components/Layout/AppLayout';
import Dashboard from './pages/Dashboard';
import Investigate from './pages/Investigate';
import BulkTriage from './pages/BulkTriage';
import History from './pages/History';
import InvestigationDetail from './pages/InvestigationDetail';
import Settings from './pages/Settings';
import Users from './pages/Users';
import Login from './pages/Login';

export default function App() {
  return (
    <ThemeProvider theme={cyberTheme}>
      <CssBaseline />
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            {/* Public authentication route */}
            <Route path="/login" element={<Login />} />

            {/* Protected application workspace */}
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <AppLayout />
                </ProtectedRoute>
              }
            >
              <Route index element={<Dashboard />} />
              <Route path="investigate" element={<Investigate />} />
              <Route path="bulk" element={<BulkTriage />} />
              <Route path="history" element={<History />} />
              <Route path="investigation/:id" element={<InvestigationDetail />} />
              <Route path="settings" element={<Settings />} />
              <Route
                path="users"
                element={
                  <ProtectedRoute allowedRoles={['Admin']}>
                    <Users />
                  </ProtectedRoute>
                }
              />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  );
}
