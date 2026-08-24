import axios from "axios";

export const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

export const apiClient = axios.create({ baseURL: API_URL });

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("vulnradar_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export function wsUrl(scanId) {
  const base = API_URL.replace(/^http/, "ws");
  return `${base}/api/scans/${scanId}/ws`;
}
