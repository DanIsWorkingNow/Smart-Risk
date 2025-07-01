// theme.js - Banking-appropriate Material-UI theme
import { createTheme } from '@mui/material/styles';

export const smartRiskTheme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',        // Professional blue
      light: '#42a5f5',
      dark: '#1565c0',
      contrastText: '#ffffff',
    },
    secondary: {
      main: '#388e3c',        // Islamic green for compliance
      light: '#66bb6a',
      dark: '#2e7d32',
      contrastText: '#ffffff',
    },
    error: {
      main: '#d32f2f',        // Non-compliance red
      light: '#ef5350',
      dark: '#c62828',
    },
    warning: {
      main: '#ff9800',        // Review required orange
      light: '#ffb74d',
      dark: '#f57c00',
    },
    success: {
      main: '#2e7d32',        // Compliant green
      light: '#4caf50',
      dark: '#1b5e20',
    },
    background: {
      default: '#f5f5f5',
      paper: '#ffffff',
    },
    text: {
      primary: '#333333',
      secondary: '#666666',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h4: {
      fontWeight: 600,
      fontSize: '2rem',
    },
    h5: {
      fontWeight: 500,
      fontSize: '1.5rem',
    },
    h6: {
      fontWeight: 500,
      fontSize: '1.25rem',
    },
    body1: {
      fontSize: '1rem',
      lineHeight: 1.5,
    },
    button: {
      textTransform: 'none',
      fontWeight: 500,
    },
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          padding: '8px 16px',
        },
        contained: {
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
          '&:hover': {
            boxShadow: '0 4px 8px rgba(0,0,0,0.15)',
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          border: '1px solid #e0e0e0',
        },
      },
    },
  },
});