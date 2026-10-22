import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 25000,
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
};

export default api;
