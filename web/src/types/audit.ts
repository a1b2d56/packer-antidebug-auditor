// Mirrors server/models/schemas.py. Keep the two in sync.

export type JobStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED"
export type Verdict = "LOW" | "MEDIUM" | "HIGH"
export type Profile = "aggressive" | "balanced" | "conservative"

export const PROFILES: { value: Profile; label: string; hint: string }[] = [
  { value: "balanced", label: "Balanced", hint: "Default thresholds (MEDIUM ≥ 3, HIGH ≥ 7)" },
  { value: "aggressive", label: "Aggressive", hint: "Threat hunting (MEDIUM ≥ 2, HIGH ≥ 5, evasion ×1.25)" },
  { value: "conservative", label: "Conservative", hint: "Fewer false positives (MEDIUM ≥ 4, HIGH ≥ 9)" },
]

export interface PEMetadata {
  arch: string
  entry_point: number
  image_base: number
  section_count: number
}

export interface SectionInfo {
  name: string
  entropy: number
  raw_size: number
  virtual_size: number
  characteristics: number
  likely_packed: boolean
  entropy_reliable?: boolean | null
  normalized_entropy?: number | null
}

/** Flag dicts emitted by auditor/ heuristics: always carry a reason, sometimes more. */
export interface Finding {
  reason: string
  section?: string
  name?: string
  kind?: string
  technique?: string
  signal_key?: string
}

export interface ImportHit {
  api: string
  reason: string
}

export interface StringHit {
  string: string
  category: string
}

export interface OverlayInfo {
  size: number
  entropy: number
  likely_packed: boolean
  reason: string
}

export interface HeuristicsResult {
  size_deltas: Finding[]
  packer_section_names: Finding[]
  rwx_sections: Finding[]
  entry_point_anomalies: Finding[]
  overlay: OverlayInfo | null
  iat_density: Finding[]
  header_anomalies: Finding[]
  section_count_flag?: Finding | null
}

export interface AntiAnalysisResult {
  imports: ImportHit[]
  strings: StringHit[]
  tls_callbacks: Finding[]
  opcodes: Finding[]
  direct_syscalls: Finding[]
}

export interface TechniqueRef {
  mitre_id: string
  mitre_name: string
}

export interface MitreTechnique {
  reason: string
  mitre_id: string | null
  mitre_name: string | null
  signal_key?: string | null
  secondary?: TechniqueRef[]
}

export interface VerdictResult {
  score: number
  verdict: Verdict
  reasons: string[]
  signal_keys: string[]
  mitre_techniques: MitreTechnique[]
  profile?: Profile | null
  thresholds?: { medium: number; high: number } | null
  confidence?: number | null
  score_interval?: [number, number] | null
  verdict_stable?: boolean | null
}

export interface MLPrediction {
  probability: number
  label: string
  confidence: number
}

export interface YaraMatch {
  rule: string
  namespace?: string | null
  description: string
  mitre_id?: string | null
  confidence?: string | null
  tags: string[]
}

export interface APKMetadata {
  package_name: string
  version_code: string
  version_name: string
  min_sdk: string
  target_sdk: string
}

export interface APKComponentInfo {
  activities: string[]
  services: string[]
  receivers: string[]
  providers: string[]
}

export interface SuspiciousApiHit {
  api: string
  reason: string
  file: string
}

export interface AuditResult {
  job_id: string
  file_name: string
  file_type: "PE" | "APK"
  sha256: string
  file_size: number
  status: JobStatus
  progress?: number | null
  pe_info?: PEMetadata | null
  sections?: SectionInfo[] | null
  heuristics?: HeuristicsResult | null
  anti_analysis?: AntiAnalysisResult | null
  verdict?: VerdictResult | null
  ml_prediction?: MLPrediction | null
  yara_matches?: YaraMatch[] | null
  apk_info?: APKMetadata | null
  apk_components?: APKComponentInfo | null
  apk_permissions?: string[] | null
  apk_endpoints?: string[] | null
  apk_suspicious_apis?: SuspiciousApiHit[] | null
  warnings?: string[]
  error?: string | null
}

export interface ProgressEvent {
  status: JobStatus
  progress: number
  message: string
}

export interface CancelResponse {
  job_id: string
  status: JobStatus
  cancelled: boolean
}

/** attack.mitre.org URL for a technique or sub-technique ID (T1027.002 -> /techniques/T1027/002/). */
export function mitreUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replaceAll(".", "/")}/`
}
