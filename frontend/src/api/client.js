import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 45000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const threatApi = {
  // Health & Providers
  getHealth: async () => {
    const res = await api.get('/health');
    return res.data;
  },
  
  getProviderStatus: async () => {
    const res = await api.get('/providers/status');
    return res.data;
  },

  // Dashboard Stats
  getDashboardStats: async () => {
    const res = await api.get('/dashboard/stats');
    return res.data;
  },

  // IOC Investigation
  investigateIOC: async (indicator, indicatorType = 'auto') => {
    const res = await api.post('/investigate', {
      indicator,
      indicator_type: indicatorType,
    });
    return res.data;
  },

  // History & Details
  getInvestigations: async (params = {}) => {
    const res = await api.get('/investigations', { params });
    return res.data;
  },

  getInvestigationById: async (id) => {
    const res = await api.get(`/investigations/${id}`);
    return res.data;
  },

  deleteInvestigation: async (id) => {
    const res = await api.delete(`/investigations/${id}`);
    return res.data;
  },

  // PDF Report Download
  downloadReportPDF: async (investigationId, fallbackFilename = 'ThreatLens_Report.pdf') => {
    const res = await api.get(`/investigations/${investigationId}/report.pdf`, {
      responseType: 'blob',
    });
    
    // Extract filename from Content-Disposition if present
    let filename = fallbackFilename;
    const disposition = res.headers['content-disposition'];
    if (disposition && disposition.includes('filename=')) {
      const match = disposition.match(/filename="?([^"]+)"?/);
      if (match && match[1]) filename = match[1];
    }

    const blob = new Blob([res.data], { type: 'application/pdf' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
    return true;
  },

  // Bulk Triage API
  previewBulkCSV: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/bulk/preview', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return res.data;
  },

  executeBulkTriage: async (items) => {
    const res = await api.post('/bulk/triage', { items });
    return res.data;
  },

  exportBulkCSV: async (results, filename = 'ThreatLens_Bulk_Triage_Results.csv') => {
    const res = await api.post('/bulk/export', { results }, {
      responseType: 'blob',
    });
    const blob = new Blob([res.data], { type: 'text/csv;charset=utf-8;' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
    return true;
  },
};

export default api;
