import axios from 'axios';

// In-memory token storage (never in localStorage to prevent XSS exfiltration)
let inMemoryAccessToken = null;

export const setAccessToken = (token) => {
  inMemoryAccessToken = token;
};

export const getAccessToken = () => inMemoryAccessToken;

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 45000,
  withCredentials: true, // Enables sending and receiving httpOnly refresh cookies
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach Authorization Bearer token to all outgoing requests if token is present
api.interceptors.request.use(
  (config) => {
    if (inMemoryAccessToken && !config.headers.Authorization) {
      config.headers.Authorization = `Bearer ${inMemoryAccessToken}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: automatically refresh on 401
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // If request failed with 401 and was NOT an auth endpoint
    if (
      error.response &&
      error.response.status === 401 &&
      originalRequest &&
      !originalRequest._retry &&
      !originalRequest.url.includes('/auth/login') &&
      !originalRequest.url.includes('/auth/refresh') &&
      !originalRequest.url.includes('/auth/logout')
    ) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            originalRequest.headers.Authorization = `Bearer ${token}`;
            return api(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const refreshRes = await api.post('/auth/refresh');
        const newToken = refreshRes.data.access_token;
        setAccessToken(newToken);
        processQueue(null, newToken);
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api(originalRequest);
      } catch (refreshErr) {
        processQueue(refreshErr, null);
        setAccessToken(null);
        // Dispatch custom session-expired event
        window.dispatchEvent(new CustomEvent('threatlens:session_expired'));
        return Promise.reject(refreshErr);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export const threatApi = {
  // Authentication
  login: async (username, password) => {
    const res = await api.post('/auth/login', { username, password });
    if (res.data && res.data.access_token) {
      setAccessToken(res.data.access_token);
    }
    return res.data;
  },

  refresh: async () => {
    const res = await api.post('/auth/refresh');
    if (res.data && res.data.access_token) {
      setAccessToken(res.data.access_token);
    }
    return res.data;
  },

  logout: async () => {
    try {
      await api.post('/auth/logout');
    } finally {
      setAccessToken(null);
    }
  },

  getMe: async () => {
    const res = await api.get('/auth/me');
    return res.data;
  },

  // User Management (Admin Only)
  getUsers: async () => {
    const res = await api.get('/users');
    return res.data;
  },

  createUser: async (userData) => {
    const res = await api.post('/users', userData);
    return res.data;
  },

  updateUser: async (userId, userData) => {
    const res = await api.patch(`/users/${userId}`, userData);
    return res.data;
  },

  deleteUser: async (userId) => {
    const res = await api.delete(`/users/${userId}`);
    return res.data;
  },

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
