// Semantic colour classes that stay legible in both light and dark themes.
export const tone = {
  danger: "bg-rose-500/10 border-rose-500/30 text-rose-700 dark:text-rose-400",
  warn: "bg-amber-500/10 border-amber-500/30 text-amber-700 dark:text-amber-400",
  ok: "bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-400",
  accent: "bg-accent/10 border-accent/30 text-accent",
  neutral: "bg-muted/60 border-border text-muted-foreground",
} as const

export const toneText = {
  danger: "text-rose-700 dark:text-rose-400",
  warn: "text-amber-700 dark:text-amber-400",
  ok: "text-emerald-700 dark:text-emerald-400",
} as const

export function verdictTone(verdict: string | undefined | null): keyof typeof toneText {
  return verdict === "HIGH" ? "danger" : verdict === "MEDIUM" ? "warn" : "ok"
}
