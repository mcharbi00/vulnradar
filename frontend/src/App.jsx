import { Route, Routes } from "react-router-dom";
import Navbar from "./components/Navbar.jsx";
import RequireAuth from "./components/RequireAuth.jsx";
import DashboardPage from "./pages/DashboardPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import ScanDetailPage from "./pages/ScanDetailPage.jsx";

export default function App() {
  return (
    <div className="min-h-screen bg-[#0b0f17]">
      <Navbar />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <DashboardPage />
            </RequireAuth>
          }
        />
        <Route
          path="/scans/:scanId"
          element={
            <RequireAuth>
              <ScanDetailPage />
            </RequireAuth>
          }
        />
      </Routes>
    </div>
  );
}
