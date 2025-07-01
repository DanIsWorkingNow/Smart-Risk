// App.js - Main application with Flask backend integration
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { AuthProvider } from './context/AuthContext';
import { smartRiskTheme } from './styles/theme';

// Import components
import LoginPage from './components/Auth/LoginPage';
import Dashboard from './components/Dashboard/Dashboard';
import ShariahAnalysis from './components/Analysis/ShariahAnalysis';
import CreditRiskAssessment from './components/Analysis/CreditRiskAssessment';
import BatchUpload from './components/FileUpload/BatchUpload';
import ProtectedRoute from './components/Auth/ProtectedRoute';

function App() {
  return (
    <ThemeProvider theme={smartRiskTheme}>
      <CssBaseline />
      <AuthProvider>
        <Router>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/" element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            } />
            <Route path="/shariah-analysis" element={
              <ProtectedRoute roles={['Shariah Risk Officer', 'System Admin']}>
                <ShariahAnalysis />
              </ProtectedRoute>
            } />
            <Route path="/credit-assessment" element={
              <ProtectedRoute roles={['Credit Risk Officer', 'System Admin']}>
                <CreditRiskAssessment />
              </ProtectedRoute>
            } />
            <Route path="/batch-upload" element={
              <ProtectedRoute>
                <BatchUpload />
              </ProtectedRoute>
            } />
          </Routes>
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;