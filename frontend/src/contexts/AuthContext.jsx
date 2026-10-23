import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { threatApi } from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Attempt initial session restore via silent cookie refresh
  useEffect(() => {
    let isMounted = true;

    async function initAuth() {
      try {
        const data = await threatApi.refresh();
        if (isMounted && data && data.user) {
          setUser(data.user);
        }
      } catch (err) {
        // No active refresh token cookie or token revoked - unauthenticated state
        if (isMounted) {
          setUser(null);
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    initAuth();

    // Listen for global session expiry triggered by API interceptor
    const handleSessionExpired = () => {
      setUser(null);
    };
    window.addEventListener('threatlens:session_expired', handleSessionExpired);

    return () => {
      isMounted = false;
      window.removeEventListener('threatlens:session_expired', handleSessionExpired);
    };
  }, []);

  const login = useCallback(async (username, password) => {
    const data = await threatApi.login(username, password);
    setUser(data.user);
    return data.user;
  }, []);

  const logout = useCallback(async () => {
    try {
      await threatApi.logout();
    } finally {
      setUser(null);
    }
  }, []);

  const refreshUser = useCallback(async () => {
    try {
      const data = await threatApi.getMe();
      setUser(data);
      return data;
    } catch (err) {
      setUser(null);
      throw err;
    }
  }, []);

  const value = {
    user,
    loading,
    isAuthenticated: Boolean(user),
    isAdmin: user?.role === 'Admin',
    isSeniorAnalyst: user?.role === 'Senior Analyst',
    isReadOnly: user?.role === 'Read-Only Analyst',
    canInvestigate: user?.role === 'Admin' || user?.role === 'Senior Analyst',
    canManageUsers: user?.role === 'Admin',
    login,
    logout,
    refreshUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
