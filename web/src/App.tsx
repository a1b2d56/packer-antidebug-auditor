import { lazy, Suspense, useEffect, useRef, useState, type FormEvent } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import {
  Upload, Shield, Loader2, RefreshCcw, Terminal, Cpu, Sparkles, CheckCircle2,
  Moon, Sun, XCircle, AlertTriangle,
} from 'lucide-react'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { ApiError, cancelJob, fetchResult, streamUrl, uploadSample } from '@/lib/api'
import { useTheme } from '@/lib/theme'
import { tone } from '@/lib/tones'
import { PROFILES, type AuditResult, type JobStatus, type Profile, type ProgressEvent } from '@/types/audit'

// The report view pulls in Recharts; load it on demand so the upload screen stays light.
const Dashboard = lazy(() => import('@/components/dashboard/Dashboard').then((m) => ({ default: m.Dashboard })))

const STAGES = [
  { at: 20, label: '1. Binary Ingestion & SHA-256 Hashing' },
  { at: 45, label: '2. Section Shannon Entropy & W^X Checks' },
  { at: 70, label: '3. Anti-Debug, Opcodes & Direct Syscall Scan' },
  { at: 90, label: '4. YARA, Random Forest Inference & ATT&CK Enrichment' },
]

function App() {
  const [theme, toggleTheme] = useTheme()
  const [file, setFile] = useState<File | null>(null)
  const [profile, setProfile] = useState<Profile>('balanced')
  const [isUploading, setIsUploading] = useState(false)
  const [jobId, setJobId] = useState<string | null>(null)

  // SSE State
  const [progress, setProgress] = useState(0)
  const [statusMessage, setStatusMessage] = useState('')
  const [result, setResult] = useState<AuditResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isCancelling, setIsCancelling] = useState(false)
  const eventSourceRef = useRef<EventSource | null>(null)

  // Listen to SSE. The server replays the full history on every (re)connect, so the
  // browser's automatic EventSource reconnection is safe and loses no progress.
  useEffect(() => {
    if (!jobId) return

    const eventSource = new EventSource(streamUrl(jobId))
    eventSourceRef.current = eventSource

    eventSource.addEventListener('progress', (e: MessageEvent<string>) => {
      const data = JSON.parse(e.data) as ProgressEvent
      setProgress(data.progress)
      setStatusMessage(data.message)
    })

    eventSource.addEventListener('done', (e: MessageEvent<string>) => {
      eventSource.close()
      const { status } = JSON.parse(e.data || '{}') as { status?: JobStatus }
      setProgress(100)
      setStatusMessage(status === 'COMPLETED' ? 'Analysis completed. Finalizing report...' : `Job ${status?.toLowerCase() ?? 'finished'}`)
      fetchResult(jobId)
        .then((final) => {
          if (final.status === 'COMPLETED') {
            setResult(final)
          } else {
            setError(final.error ?? `Audit ${final.status.toLowerCase()}`)
            setJobId(null)
          }
        })
        .catch((err: unknown) => {
          setError(err instanceof Error ? err.message : 'Failed to fetch the final report')
          setJobId(null)
        })
    })

    eventSource.onerror = () => {
      if (eventSource.readyState === EventSource.CLOSED) {
        setError('Lost the live progress stream from the analysis server.')
        setJobId(null)
      } else {
        setStatusMessage('Connection interrupted — reconnecting...')
      }
    }

    return () => {
      eventSource.close()
      eventSourceRef.current = null
    }
  }, [jobId])

  const handleUpload = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!file) return
    setIsUploading(true)
    setResult(null)
    setError(null)
    setJobId(null)
    setProgress(0)
    setStatusMessage('Uploading file to sandbox...')

    try {
      const data = await uploadSample(file, profile)
      if (data.status === 'COMPLETED') {
        setResult(data)
        setProgress(100)
        setStatusMessage('Cached signature result loaded.')
      } else {
        setJobId(data.job_id)
      }
    } catch (err) {
      setError(err instanceof ApiError || err instanceof Error ? err.message : 'Upload failed.')
    } finally {
      setIsUploading(false)
    }
  }

  const handleCancel = async () => {
    if (!jobId) return
    setIsCancelling(true)
    try {
      await cancelJob(jobId)
      eventSourceRef.current?.close()
      setError('Audit cancelled.')
      setJobId(null)
    } catch (err) {
      setStatusMessage(err instanceof Error ? `Cancel failed: ${err.message}` : 'Cancel failed')
    } finally {
      setIsCancelling(false)
    }
  }

  const reset = () => {
    setFile(null)
    setResult(null)
    setError(null)
    setJobId(null)
    setProgress(0)
    setStatusMessage('')
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col font-sans">
      <header className="border-b border-border/80 bg-card/80 backdrop-blur-md sticky top-0 z-20">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className={`w-9 h-9 shrink-0 rounded-lg border flex items-center justify-center ${tone.accent}`}>
              <Shield className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <span className="block truncate font-bold tracking-tight text-base sm:text-lg text-foreground">
                Packer & Anti-Debug Auditor
              </span>
              <p className="text-[11px] text-muted-foreground hidden sm:block">
                Static Triage, Direct Syscall Detection & ML Classification
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs">
            <div className="text-right hidden sm:block">
              <span className="text-foreground font-medium text-xs block">Ananmay Jha & Aaditya Agre</span>
              <span className="text-[10px] text-muted-foreground font-mono">23BCI0163 • 23BCI0146</span>
            </div>
            <Button
              variant="outline"
              size="icon"
              onClick={toggleTheme}
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
              title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
              className="h-9 w-9 shrink-0"
            >
              {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </Button>
          </div>
        </div>
      </header>

      <main className="flex-1 container mx-auto px-4 py-8 flex flex-col items-center">
        {error && !jobId && !result && (
          <div role="alert" className={`w-full max-w-2xl mb-4 flex items-start gap-2 rounded-lg border p-3 text-sm ${tone.danger}`}>
            <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
            <span className="break-words">{error}</span>
          </div>
        )}

        {!jobId && !result && (
          <div className="w-full max-w-2xl space-y-6 mt-4 animate-in fade-in slide-in-from-bottom-2 duration-400">
            <div className="text-center space-y-2 py-4">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-muted/60 border border-border text-xs text-muted-foreground mb-1 font-mono">
                <Sparkles className="w-3.5 h-3.5 text-accent" />
                <span>Dual-Engine Triage: Heuristic Rules + Random Forest ML</span>
              </div>
              <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground">
                Automated Malware & APK Triage
              </h2>
              <p className="text-sm text-muted-foreground max-w-lg mx-auto">
                Scan Windows PE (EXE/DLL) and Android APKs for packing, W^X violations, direct syscalls
                (Hell's/Halo's/Tartarus Gate, Heaven's Gate), and anti-analysis evasion.
              </p>
            </div>

            <Card className="border border-border/80 bg-card shadow-xl shadow-black/5 dark:shadow-black/30">
              <CardHeader className="pb-4">
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <CardTitle className="text-base text-foreground flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-accent" />
                      Submit Binary Sample
                    </CardTitle>
                    <CardDescription className="text-xs mt-1">
                      Drag and drop target artifact or select from disk
                    </CardDescription>
                  </div>
                  <Badge variant="outline" className="font-mono text-[11px] border-border text-muted-foreground shrink-0">
                    Static only
                  </Badge>
                </div>
              </CardHeader>

              <CardContent>
                <form onSubmit={handleUpload} className="space-y-5">
                  <div className="border border-dashed border-border/90 rounded-lg p-6 sm:p-8 flex flex-col items-center justify-center bg-muted/20 hover:bg-muted/40 transition-colors relative group cursor-pointer">
                    <input
                      type="file"
                      aria-label="Binary sample"
                      className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                      onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                      accept=".exe,.dll,.sys,.apk"
                    />
                    <div className={`w-12 h-12 rounded-full border flex items-center justify-center mb-3 group-hover:scale-105 transition-transform ${tone.accent}`}>
                      <Upload className="w-5 h-5" />
                    </div>
                    <p className="text-sm text-foreground mb-1 text-center font-medium">
                      Drop binary executable here, or browse files
                    </p>
                    <p className="text-xs text-muted-foreground text-center font-mono">
                      PE (.exe, .dll, .sys) & Android APK (.apk) • Up to 100 MB
                    </p>
                    {file && (
                      <div className={`mt-4 max-w-full px-3 py-1.5 rounded-md border text-xs font-mono flex items-center gap-2 ${tone.accent}`}>
                        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                        <span className="truncate">
                          Selected: <span className="font-bold underline">{file.name}</span> ({(file.size / 1024).toFixed(1)} KB)
                        </span>
                      </div>
                    )}
                  </div>

                  <fieldset className="space-y-2">
                    <legend className="text-xs font-mono uppercase tracking-wider text-muted-foreground mb-2">
                      Scoring sensitivity profile
                    </legend>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                      {PROFILES.map((p) => (
                        <label
                          key={p.value}
                          className={`cursor-pointer rounded-md border p-2.5 text-xs transition-colors ${
                            profile === p.value ? tone.accent : 'border-border hover:bg-muted/40 text-foreground'
                          }`}
                        >
                          <input
                            type="radio"
                            name="profile"
                            value={p.value}
                            checked={profile === p.value}
                            onChange={() => setProfile(p.value)}
                            className="sr-only"
                          />
                          <span className="block font-semibold">{p.label}</span>
                          <span className="block text-[11px] text-muted-foreground mt-0.5">{p.hint}</span>
                        </label>
                      ))}
                    </div>
                  </fieldset>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-center text-[11px] text-muted-foreground font-mono pt-1 border-t border-border/60">
                    <div className="py-1">
                      <span className="text-foreground block font-semibold">22 Static Signals</span>
                      W^X, IAT, TLS, Entropy, Syscalls
                    </div>
                    <div className="py-1 sm:border-x border-border/60">
                      <span className="text-foreground block font-semibold">YARA Rule Engine</span>
                      MITRE ATT&CK Mapped
                    </div>
                    <div className="py-1">
                      <span className="text-foreground block font-semibold">Heuristic Confidence</span>
                      Leave-one-out score interval
                    </div>
                  </div>

                  <Button
                    type="submit"
                    className="w-full font-bold"
                    size="lg"
                    disabled={!file || isUploading}
                  >
                    {isUploading ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Uploading sample...
                      </>
                    ) : (
                      'Execute Multi-Engine Audit'
                    )}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>
        )}

        {jobId && !result && (
          <div className="w-full max-w-lg mt-8 sm:mt-12 animate-in zoom-in-95 duration-300">
            <Card className="border border-border/80 bg-card shadow-2xl shadow-black/5 dark:shadow-black/40">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base text-foreground flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-accent animate-pulse" />
                    Real-Time Pipeline Execution
                  </CardTitle>
                  <span className="text-xs font-mono text-accent font-bold">{progress}%</span>
                </div>
                <CardDescription className="text-xs truncate">
                  Analyzing: <span className="font-mono text-foreground">{file?.name ?? 'Target Binary'}</span> • profile {profile}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="space-y-2">
                  <Progress value={progress} className="h-2 bg-muted/60" />
                  <div className="flex justify-between items-center gap-2 text-xs font-mono">
                    <span className="text-foreground flex items-center gap-1.5 min-w-0">
                      <span className="w-1.5 h-1.5 shrink-0 rounded-full bg-accent animate-ping"></span>
                      <span className="truncate">{statusMessage || 'Processing stages...'}</span>
                    </span>
                    <span className="text-muted-foreground shrink-0">SSE live</span>
                  </div>
                </div>

                <div className="p-3 rounded bg-muted/40 border border-border/60 text-[11px] font-mono space-y-1">
                  <div className="text-muted-foreground uppercase text-[10px] tracking-wider mb-1">Audit Stages:</div>
                  {STAGES.map((stage) => (
                    <div key={stage.at} className={progress >= stage.at ? 'text-accent' : 'text-muted-foreground'}>
                      {progress >= stage.at ? '✓' : '○'} {stage.label}
                    </div>
                  ))}
                </div>

                <Button variant="outline" className="w-full text-xs" onClick={handleCancel} disabled={isCancelling}>
                  {isCancelling ? <Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" /> : <XCircle className="w-3.5 h-3.5 mr-2" />}
                  Cancel audit
                </Button>
              </CardContent>
            </Card>
          </div>
        )}

        {result && (
          <div className="w-full max-w-5xl space-y-5">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-2 border-b border-border/80">
              <div className="min-w-0 max-w-full">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline" className={`font-mono text-[11px] ${tone.accent}`}>
                    {result.file_type} AUDIT REPORT
                  </Badge>
                  <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground truncate max-w-full sm:max-w-xl">
                    {result.file_name}
                  </h2>
                </div>
                <p className="text-xs font-mono text-muted-foreground mt-0.5 break-all">
                  Job ID: {result.job_id} • Status: {result.status}
                </p>
              </div>

              <Button variant="outline" onClick={reset} className="text-xs h-9 font-medium shrink-0">
                <RefreshCcw className="w-3.5 h-3.5 mr-2" />
                Analyze Another Sample
              </Button>
            </div>

            <ErrorBoundary onReset={reset}>
              <Suspense
                fallback={
                  <div className="flex items-center justify-center gap-2 py-16 text-xs font-mono text-muted-foreground">
                    <Loader2 className="w-4 h-4 animate-spin" /> Loading report view...
                  </div>
                }
              >
                <Dashboard result={result} />
              </Suspense>
            </ErrorBoundary>
          </div>
        )}
      </main>

      <footer className="border-t border-border/60 py-4 px-4 text-center text-xs text-muted-foreground font-mono">
        Final Review • Ananmay Jha (23BCI0163) & Aaditya Agre (23BCI0146)
      </footer>
    </div>
  )
}

export default App
