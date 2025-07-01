// api.js - Central API configuration for Flask backend integration
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:5000/api';

// Create axios instance with default configuration
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: parseInt(process.env.REACT_APP_API_TIMEOUT) || 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add authentication token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('smart_risk_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      localStorage.removeItem('smart_risk_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// API service functions for SMART-Risk backend integration
export const smartRiskAPI = {
  // Authentication endpoints
  auth: {
    login: (credentials) => apiClient.post('/auth/login', credentials),
    logout: () => apiClient.post('/auth/logout'),
    validateToken: () => apiClient.get('/auth/validate'),
  },

  // Shariah Risk Analysis endpoints
  shariahRisk: {
    analyze: (analysisData) => apiClient.post('/shariah-analysis', analysisData),
    getHistory: (params) => apiClient.get('/shariah-analysis/history', { params }),
    getAssessment: (id) => apiClient.get(`/shariah-analysis/${id}`),
  },

  // Credit Risk Assessment endpoints
  creditRisk: {
    calculate: (riskData) => apiClient.post('/credit-risk/calculate', riskData),
    batchProcess: (fileData) => apiClient.post('/credit-risk/batch', fileData),
    getAssessment: (id) => apiClient.get(`/credit-risk/${id}`),
  },

  // File Upload endpoints
  fileUpload: {
    uploadBatch: (formData) => 
      apiClient.post('/upload/batch', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    getUploadHistory: () => apiClient.get('/upload/history'),
    downloadTemplate: (type) => apiClient.get(`/upload/template/${type}`, {
      responseType: 'blob',
    }),
  },

  // User Management endpoints (Admin only)
  users: {
    getAll: () => apiClient.get('/users'),
    create: (userData) => apiClient.post('/users', userData),
    update: (id, userData) => apiClient.put(`/users/${id}`, userData),
    delete: (id) => apiClient.delete(`/users/${id}`),
  },

  // Reports endpoints
  reports: {
    generate: (reportData) => apiClient.post('/reports/generate', reportData),
    download: (reportId) => apiClient.get(`/reports/${reportId}/download`, {
      responseType: 'blob',
    }),
    getList: () => apiClient.get('/reports'),
  },

  // Dashboard data endpoints
  dashboard: {
    getStatistics: () => apiClient.get('/dashboard/statistics'),
    getRecentActivity: () => apiClient.get('/dashboard/recent-activity'),
    getSystemHealth: () => apiClient.get('/dashboard/system-health'),
  },
};

export default apiClient;