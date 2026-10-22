import { createTheme } from '@mui/material/styles';

export const cyberTheme = createTheme({
  palette: {
    mode: 'dark',
    background: {
      default: '#080c14',
      paper: '#0f172a',
    },
    primary: {
      main: '#00f2fe',
      light: '#38bdf8',
      dark: '#0284c7',
      contrastText: '#080c14',
    },
    secondary: {
      main: '#6366f1',
      light: '#818cf8',
      dark: '#4f46e5',
      contrastText: '#ffffff',
    },
    success: {
      main: '#10b981',
      light: '#34d399',
      dark: '#059669',
    },
    warning: {
      main: '#f59e0b',
      light: '#fbbf24',
      dark: '#d97706',
    },
    error: {
      main: '#ef4444',
      light: '#f87171',
      dark: '#dc2626',
    },
    info: {
      main: '#38bdf8',
      light: '#7dd3fc',
      dark: '#0284c7',
    },
    text: {
      primary: '#f1f5f9',
      secondary: '#94a3b8',
      disabled: '#475569',
    },
    divider: 'rgba(255, 255, 255, 0.08)',
  },
  typography: {
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    h1: { fontWeight: 700, letterSpacing: '-0.025em' },
    h2: { fontWeight: 700, letterSpacing: '-0.02em' },
    h3: { fontWeight: 600, letterSpacing: '-0.015em' },
    h4: { fontWeight: 600, letterSpacing: '-0.01em' },
    h5: { fontWeight: 600 },
    h6: { fontWeight: 600 },
    button: { textTransform: 'none', fontWeight: 600 },
  },
  shape: {
    borderRadius: 8,
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundColor: '#080c14',
          color: '#f1f5f9',
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: '#0f172a',
          backgroundImage: 'linear-gradient(rgba(255, 255, 255, 0.02), rgba(255, 255, 255, 0))',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: 12,
          transition: 'all 0.2s ease-in-out',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          padding: '8px 18px',
          fontWeight: 600,
        },
        containedPrimary: {
          background: 'linear-gradient(135deg, #00f2fe 0%, #0284c7 100%)',
          color: '#080c14',
          boxShadow: '0 0 15px rgba(0, 242, 254, 0.25)',
          '&:hover': {
            boxShadow: '0 0 25px rgba(0, 242, 254, 0.45)',
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontWeight: 500,
          borderRadius: 6,
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
          padding: '12px 16px',
        },
        head: {
          fontWeight: 600,
          color: '#94a3b8',
          backgroundColor: '#0c1322',
        },
      },
    },
  },
});
