const STYLES = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  low: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  info: "bg-slate-500/20 text-slate-300 border-slate-500/40",
};

export default function SeverityBadge({ severity }) {
  const style = STYLES[severity] || STYLES.info;
  return (
    <span className={`inline-block rounded-full border px-2.5 py-0.5 text-xs font-medium uppercase tracking-wide ${style}`}>
      {severity}
    </span>
  );
}
