import { useCallback, useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { apiClient, wsUrl } from "../api/client";
import ProgressBar from "../components/ProgressBar.jsx";
import ScoreGauge from "../components/ScoreGauge.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";

const CATEGORY_LABELS = {
  headers: "En-têtes de sécurité",
  cookies: "Cookies",
  tls: "TLS / HTTPS",
  ports: "Ports ouverts",
  xss: "XSS réfléchi",
  sqli: "Injection SQL",
  dirs: "Fichiers exposés",
  methods: "Méthodes HTTP",
  cors: "Configuration CORS",
  engine: "Moteur de scan",
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const SEVERITY_LABELS = {
  critical: "critique",
  high: "élevée",
  medium: "moyenne",
  low: "faible",
  info: "info",
};

const SEVERITY_TEXT = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-slate-400",
};

export default function ScanDetailPage() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [liveStep, setLiveStep] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const wsRef = useRef(null);

  const loadScan = useCallback(async () => {
    const { data } = await apiClient.get(`/api/scans/${scanId}`);
    setScan(data);
    return data;
  }, [scanId]);

  useEffect(() => {
    let cancelled = false;

    loadScan();

    const socket = new WebSocket(wsUrl(scanId));
    wsRef.current = socket;
    socket.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === "progress") {
        setLiveStep(msg.step);
        setScan((prev) => (prev ? { ...prev, progress: msg.progress, status: "running" } : prev));
      } else if (msg.type === "completed" || msg.type === "failed") {
        loadScan();
      }
    };

    // Filet de sécurité si le WebSocket ne délivre pas tout : on repolle
    // tant que le scan n'est pas terminé.
    const interval = setInterval(async () => {
      if (cancelled) return;
      const data = await loadScan();
      if (data.status === "completed" || data.status === "failed") {
        clearInterval(interval);
      }
    }, 2000);

    return () => {
      cancelled = true;
      socket.close();
      clearInterval(interval);
    };
  }, [scanId, loadScan]);

  const handleExportPdf = async () => {
    const response = await apiClient.get(`/api/scans/${scanId}/report.pdf`, {
      responseType: "blob",
    });
    const url = window.URL.createObjectURL(response.data);
    const link = document.createElement("a");
    link.href = url;
    link.download = `vulnradar-scan-${scanId}.pdf`;
    link.click();
    window.URL.revokeObjectURL(url);
  };

  if (!scan) {
    return <div className="mx-auto max-w-4xl px-4 py-8 text-slate-400">Chargement…</div>;
  }

  // compte le nombre de findings par gravité (pour afficher sur les boutons)
  const counts = scan.findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  // n'affiche que les findings de la gravité choisie ("all" = toutes)
  const visibleFindings =
    severityFilter === "all"
      ? scan.findings
      : scan.findings.filter((f) => f.severity === severityFilter);

  const grouped = visibleFindings.reduce((acc, f) => {
    acc[f.category] = acc[f.category] || [];
    acc[f.category].push(f);
    return acc;
  }, {});

  return (
    <div className="mx-auto max-w-4xl px-4 py-8">
      <div className="mb-6 rounded-xl border border-slate-800 bg-panel p-6">
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div>
            <h1 className="text-lg font-semibold text-slate-100">{scan.target}</h1>
            <p className="text-sm text-slate-500">
              Lancé le {new Date(scan.started_at).toLocaleString("fr-FR")}
            </p>
            {scan.status === "running" && liveStep && (
              <p className="mt-2 text-sm text-accent">Étape en cours : {liveStep}</p>
            )}
            {scan.status === "failed" && (
              <p className="mt-2 text-sm text-red-400">Erreur : {scan.error}</p>
            )}
          </div>
          <div className="flex flex-col items-end gap-3">
            <ScoreGauge score={scan.score} />
            {scan.status === "completed" && (
              <button
                onClick={handleExportPdf}
                className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800"
              >
                Exporter en PDF
              </button>
            )}
          </div>
        </div>
        <div className="mt-4">
          <ProgressBar progress={scan.progress} status={scan.status} />
        </div>
      </div>

      {scan.findings.length === 0 && scan.status === "completed" && (
        <p className="rounded-lg border border-emerald-800 bg-emerald-500/10 p-4 text-sm text-emerald-300">
          Aucune vulnérabilité détectée par les modules disponibles. 🎉
        </p>
      )}

      {scan.findings.length > 0 && (
        <div className="mb-4 flex flex-wrap gap-x-5 gap-y-1 text-sm">
          {SEVERITIES.filter((s) => counts[s]).map((s) => (
            <span key={s} className={SEVERITY_TEXT[s]}>
              <strong>{counts[s]}</strong> {SEVERITY_LABELS[s]}
              {counts[s] > 1 ? "s" : ""}
            </span>
          ))}
        </div>
      )}

      {scan.findings.length > 0 && (
        <div className="mb-4 flex flex-wrap gap-2">
          <button
            onClick={() => setSeverityFilter("all")}
            className={`rounded-full border px-3 py-1 text-xs ${
              severityFilter === "all"
                ? "border-accent text-accent"
                : "border-slate-700 text-slate-400 hover:bg-slate-800"
            }`}
          >
            Toutes ({scan.findings.length})
          </button>
          {SEVERITIES.filter((s) => counts[s]).map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={`rounded-full border px-3 py-1 text-xs uppercase ${
                severityFilter === s
                  ? "border-accent text-accent"
                  : "border-slate-700 text-slate-400 hover:bg-slate-800"
              }`}
            >
              {s} ({counts[s]})
            </button>
          ))}
        </div>
      )}

      <div className="space-y-6">
        {Object.entries(grouped).map(([category, findings]) => (
          <div key={category} className="rounded-xl border border-slate-800 bg-panel p-4">
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">
              {CATEGORY_LABELS[category] || category}
            </h2>
            <div className="space-y-3">
              {findings.map((f) => (
                <div key={f.id} className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-100">{f.title}</span>
                    <SeverityBadge severity={f.severity} />
                  </div>
                  <p className="text-sm text-slate-400">{f.description}</p>
                  {f.evidence && (
                    <pre className="mt-2 overflow-x-auto rounded bg-black/40 p-2 text-xs text-slate-500">
                      {f.evidence}
                    </pre>
                  )}
                  {f.recommendation && (
                    <p className="mt-2 text-xs text-accent">→ {f.recommendation}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
