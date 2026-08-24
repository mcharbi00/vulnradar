export default function ScoreGauge({ score }) {
  if (score === null || score === undefined) {
    return <div className="text-slate-500 text-sm">Score en attente…</div>;
  }

  const color = score >= 80 ? "text-emerald-400" : score >= 50 ? "text-yellow-400" : "text-red-400";

  return (
    <div className="flex items-center gap-3">
      <div className={`text-4xl font-bold ${color}`}>{score}</div>
      <div className="text-slate-400 text-sm">/ 100</div>
    </div>
  );
}
