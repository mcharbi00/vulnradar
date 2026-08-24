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
  engine: "Moteur de scan",
};

export default function ScanDetailPage() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [liveStep, setLiveStep] = useState(null);
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

  if (!scan) {
    return <div className="mx-auto max-w-4xl px-4 py-8 text-slate-400">Chargement…</div>;
  }

  const grouped = scan.findings.reduce((acc, f) => {
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
          <ScoreGauge score={scan.score} />
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
