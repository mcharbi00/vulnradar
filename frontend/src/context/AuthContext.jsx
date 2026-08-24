import { createContext, useContext, useMemo, useState } from "react";
import { apiClient } from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem("vulnradar_token"));
  const [username, setUsername] = useState(() => localStorage.getItem("vulnradar_username"));

  const login = async (usernameInput, password) => {
    const form = new URLSearchParams();
    form.append("username", usernameInput);
    form.append("password", password);
    const { data } = await apiClient.post("/api/auth/login", form, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    localStorage.setItem("vulnradar_token", data.access_token);
    localStorage.setItem("vulnradar_username", usernameInput);
    setToken(data.access_token);
    setUsername(usernameInput);
  };

  const register = async (usernameInput, password) => {
    await apiClient.post("/api/auth/register", { username: usernameInput, password });
    await login(usernameInput, password);
  };

  const logout = () => {
    localStorage.removeItem("vulnradar_token");
    localStorage.removeItem("vulnradar_username");
    setToken(null);
    setUsername(null);
  };

  const value = useMemo(
    () => ({ token, username, isAuthenticated: Boolean(token), login, register, logout }),
    [token, username]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth doit être utilisé dans <AuthProvider>");
  return ctx;
}
