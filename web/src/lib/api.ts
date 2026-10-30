import type { AuditResult, CancelResponse, Profile } from "@/types/audit"

export const API_BASE: string = (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://127.0.0.1:8000"

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}`, init)
  } catch {
    throw new ApiError(0, `Cannot reach the analysis server at ${API_BASE}. Is it running?`)
  }
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body: unknown = await res.json()
      if (body && typeof body === "object" && "detail" in body) {
        detail = String((body as { detail: unknown }).detail)
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail || `HTTP ${res.status}`)
  }
  return (await res.json()) as T
}

export function uploadSample(file: File, profile: Profile): Promise<AuditResult> {
  const form = new FormData()
  form.append("file", file)
  form.append("profile", profile)
  return request<AuditResult>("/api/v1/upload", { method: "POST", body: form })
}

export function fetchResult(jobId: string): Promise<AuditResult> {
  return request<AuditResult>(`/api/v1/audit/${encodeURIComponent(jobId)}`)
}

export function cancelJob(jobId: string): Promise<CancelResponse> {
  return request<CancelResponse>(`/api/v1/audit/${encodeURIComponent(jobId)}`, { method: "DELETE" })
}

export function streamUrl(jobId: string): string {
  return `${API_BASE}/api/v1/audit/${encodeURIComponent(jobId)}/stream`
}
