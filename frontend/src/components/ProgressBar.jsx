export default function ProgressBar({ progress = 0, status = "pending" }) {
  const colors = {
    completed: "bg-emerald-500",
    failed: "bg-red-500",
    running: "bg-accent",
    pending: "bg-slate-500",
  };

  return (
    <div className="w-full">
      <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full rounded-full transition-all duration-300 ${colors[status] || colors.pending}`}
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="mt-1 text-xs text-slate-500">{progress}%</div>
    </div>
  );
}
