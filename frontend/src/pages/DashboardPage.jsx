import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiClient } from "../api/client";
import ProgressBar from "../components/ProgressBar.jsx";
import ScoreGauge from "../components/ScoreGauge.jsx";

const STATUS_LABELS = {
  pending: "En attente",
  running: "En cours",
  completed: "Terminé",
  failed: "Échoué",
};

export default function DashboardPage() {
  const [scans, setScans] = useState([]);
  const [target, setTarget] = useState("demo-target");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const loadScans = async () => {
    const { data } = await apiClient.get("/api/scans");
    setScans(data);
  };

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleNewScan = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const { data } = await apiClient.post("/api/scans", { target });
      navigate(`/scans/${data.id}`);
    } catch (err) {
      setError(err.response?.data?.detail || "Impossible de lancer le scan.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <div className="mb-8 rounded-xl border border-slate-800 bg-panel p-6">
        <h1 className="mb-4 text-lg font-semibold text-slate-100">Nouveau scan</h1>
        <form onSubmit={handleNewScan} className="flex flex-col gap-3 sm:flex-row">
          <input
            className="flex-1 rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-accent focus:outline-none"
            placeholder="ex: demo-target, localhost:8001"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            required
          />
          <button
            type="submit"
            disabled={loading}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-slate-900 hover:opacity-90 disabled:opacity-50"
          >
            {loading ? "Lancement…" : "Lancer le scan"}
          </button>
        </form>
        {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
        <p className="mt-3 text-xs text-slate-500">
          Par sécurité, seules les cibles listées dans <code>ALLOWED_SCAN_HOSTS</code> côté
          serveur sont autorisées (par défaut : demo-target, localhost, 127.0.0.1).
        </p>
      </div>

      <h2 className="mb-3 text-lg font-semibold text-slate-100">Historique des scans</h2>
      {scans.length === 0 && (
        <p className="text-sm text-slate-500">Aucun scan pour le moment — lance ton premier scan ci-dessus.</p>
      )}
      <div className="space-y-3">
        {scans.map((scan) => (
          <Link
            key={scan.id}
            to={`/scans/${scan.id}`}
            className="block rounded-xl border border-slate-800 bg-panel p-4 transition hover:border-accent/60"
          >
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <div className="font-medium text-slate-100">{scan.target}</div>
                <div className="text-xs text-slate-500">
                  {STATUS_LABELS[scan.status]} · {new Date(scan.started_at).toLocaleString("fr-FR")}
                </div>
              </div>
              <div className="flex items-center gap-6">
                <div className="w-40">
                  <ProgressBar progress={scan.progress} status={scan.status} />
                </div>
                <ScoreGauge score={scan.score} />
              </div>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
