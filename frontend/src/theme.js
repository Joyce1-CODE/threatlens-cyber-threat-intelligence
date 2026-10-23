import { createTheme } from '@mui/material/styles';

export const cyberTheme = createTheme({
  palette: {
    mode: 'light',
    background: {
      default: '#F5F7FB',
      paper: '#FFFFFF',
    },
    primary: {
      main: '#0891B2',
      light: '#06B6D4',
      dark: '#0E7490',
      contrastText: '#FFFFFF',
    },
    secondary: {
      main: '#4F46E5',
      light: '#6366F1',
      dark: '#4338CA',
      contrastText: '#FFFFFF',
    },
    success: {
      main: '#16A34A',
      light: '#22C55E',
      dark: '#15803D',
      contrastText: '#FFFFFF',
    },
    warning: {
      main: '#D97706',
      light: '#F59E0B',
      dark: '#B45309',
      contrastText: '#FFFFFF',
    },
    error: {
      main: '#DC2626',
      light: '#EF4444',
      dark: '#B91C1C',
      contrastText: '#FFFFFF',
    },
    info: {
      main: '#0891B2',
      light: '#06B6D4',
      dark: '#0E7490',
      contrastText: '#FFFFFF',
    },
    text: {
      primary: '#172B4D',
      secondary: '#64748B',
      disabled: '#94A3B8',
    },
    divider: '#DCE4EE',
  },
  typography: {
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    h1: { fontWeight: 700, letterSpacing: '-0.025em', color: '#172B4D' },
    h2: { fontWeight: 700, letterSpacing: '-0.02em', color: '#172B4D' },
    h3: { fontWeight: 600, letterSpacing: '-0.015em', color: '#172B4D' },
    h4: { fontWeight: 600, letterSpacing: '-0.01em', color: '#172B4D' },
    h5: { fontWeight: 600, color: '#172B4D' },
    h6: { fontWeight: 600, color: '#172B4D' },
    subtitle1: { color: '#172B4D' },
    subtitle2: { color: '#172B4D' },
    body1: { color: '#172B4D' },
    body2: { color: '#64748B' },
    button: { textTransform: 'none', fontWeight: 600 },
  },
  shape: {
    borderRadius: 8,
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundColor: '#F5F7FB',
          color: '#172B4D',
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: '#FFFFFF',
          backgroundImage: 'none',
          border: '1px solid #DCE4EE',
          borderRadius: 10,
          boxShadow: '0 1px 3px rgba(15, 23, 42, 0.05), 0 1px 2px rgba(15, 23, 42, 0.03)',
          transition: 'all 0.2s ease-in-out',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: '#FFFFFF',
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
          backgroundColor: '#0891B2',
          color: '#FFFFFF',
          boxShadow: '0 1px 2px rgba(8, 145, 178, 0.2)',
          '&:hover': {
            backgroundColor: '#0E7490',
            boxShadow: '0 2px 6px rgba(8, 145, 178, 0.3)',
          },
        },
        outlined: {
          borderColor: '#DCE4EE',
          color: '#172B4D',
          '&:hover': {
            borderColor: '#0891B2',
            backgroundColor: 'rgba(8, 145, 178, 0.04)',
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
          borderBottom: '1px solid #DCE4EE',
          padding: '12px 16px',
          color: '#172B4D',
        },
        head: {
          fontWeight: 600,
          color: '#64748B',
          backgroundColor: '#F8FAFC',
          borderBottom: '1px solid #DCE4EE',
        },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          backgroundColor: '#FFFFFF',
          color: '#172B4D',
          '& fieldset': {
            borderColor: '#DCE4EE',
          },
          '&:hover fieldset': {
            borderColor: '#0891B2',
          },
          '&.Mui-focused fieldset': {
            borderColor: '#0891B2',
          },
        },
      },
    },
    MuiDivider: {
      styleOverrides: {
        root: {
          borderColor: '#DCE4EE',
        },
      },
    },
  },
});
