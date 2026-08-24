import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";

export default function Navbar() {
  const { isAuthenticated, username, logout } = useAuth();

  return (
    <nav className="border-b border-slate-800 bg-panel/60 backdrop-blur">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
        <Link to="/" className="flex items-center gap-2 font-semibold text-slate-100">
          <span className="text-accent">◎</span> VulnRadar
        </Link>
        {isAuthenticated && (
          <div className="flex items-center gap-4 text-sm">
            <span className="text-slate-400">Connecté·e en tant que {username}</span>
            <button
              onClick={logout}
              className="rounded-md border border-slate-700 px-3 py-1 text-slate-300 hover:bg-slate-800"
            >
              Déconnexion
            </button>
          </div>
        )}
      </div>
    </nav>
  );
}
