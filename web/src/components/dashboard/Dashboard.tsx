import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'
import {
  ShieldAlert, ShieldCheck, FileCode, Box, Fingerprint,
  Lock, Unlock, ExternalLink, Activity, AlertTriangle,
  CheckCircle2, Terminal, Code2, Layers, Gauge, Zap,
} from 'lucide-react'
import { tone, toneText, verdictTone } from '@/lib/tones'
import { mitreUrl, type AuditResult, type MitreTechnique } from '@/types/audit'

export type { AuditResult } from '@/types/audit'

function formatEntropy(value: number | null | undefined): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(3) : '—'
}

interface MitreEntry {
  id: string
  name: string
  sources: string[]
}

/** Unique techniques (primary + secondary), each listing the signals that evidenced it. */
function collectTechniques(techniques: MitreTechnique[] | undefined, extra: { id?: string | null; source: string }[]): MitreEntry[] {
  const byId = new Map<string, MitreEntry>()
  const add = (id: string | null | undefined, name: string | null | undefined, source: string) => {
    if (!id) return
    const entry = byId.get(id) ?? { id, name: name ?? '', sources: [] }
    if (!entry.name && name) entry.name = name
    if (!entry.sources.includes(source)) entry.sources.push(source)
    byId.set(id, entry)
  }
  for (const t of techniques ?? []) {
    const source = t.signal_key ?? 'signal'
    add(t.mitre_id, t.mitre_name, source)
    for (const s of t.secondary ?? []) add(s.mitre_id, s.mitre_name, source)
  }
  for (const e of extra) add(e.id, null, e.source)
  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id))
}

export function Dashboard({ result }: { result: AuditResult }) {
  const {
    verdict, ml_prediction, file_type, sha256, file_size,
    sections, anti_analysis, apk_permissions, apk_endpoints, apk_info,
    apk_suspicious_apis, yara_matches, pe_info, warnings,
  } = result

  const vTone = verdictTone(verdict?.verdict)
  const isHighRisk = verdict?.verdict === 'HIGH'
  const isMediumRisk = verdict?.verdict === 'MEDIUM'
  const VerdictIcon = isHighRisk ? ShieldAlert : isMediumRisk ? AlertTriangle : ShieldCheck

  // ML donut: series colours come from theme tokens so both themes stay legible
  const prob = ml_prediction?.probability ?? 0
  const mlData = [
    { name: 'Packed', value: Number((prob * 100).toFixed(1)), fill: '#F43F5E' },
    { name: 'Clean', value: Number(((1 - prob) * 100).toFixed(1)), fill: 'hsl(var(--muted))' },
  ]

  const mitreList = collectTechniques(
    verdict?.mitre_techniques,
    (yara_matches ?? []).map((m) => ({ id: m.mitre_id, source: `yara:${m.rule}` })),
  )
  const syscalls = anti_analysis?.direct_syscalls ?? []
  const confidencePct = verdict?.confidence != null ? Math.round(verdict.confidence * 100) : null

  return (
    <div className="space-y-5 animate-in fade-in duration-300">
      {warnings && warnings.length > 0 && (
        <div className={`rounded-lg border p-3 text-xs font-mono space-y-1 ${tone.warn}`} role="status">
          {warnings.map((w) => (
            <div key={w} className="flex items-start gap-2">
              <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
              <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Card 1: Heuristic Verdict */}
        <Card className="border border-border/80 bg-card/90 shadow-md">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase text-muted-foreground tracking-wider">
                Heuristic Verdict
              </span>
              <span className={`text-[11px] font-mono px-2 py-0.5 rounded-full border font-semibold ${tone[vTone]}`}>
                {verdict?.verdict ?? 'UNKNOWN'}
              </span>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg bg-card border border-border/80 ${toneText[vTone]}`}>
                <VerdictIcon className="w-7 h-7" />
              </div>
              <div>
                <div className="text-2xl font-bold font-mono tracking-tight text-foreground">
                  Risk Score: {verdict?.score ?? 0}
                </div>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {isHighRisk
                    ? 'Critical packing or evasion signatures detected'
                    : isMediumRisk
                    ? 'Suspicious structural anomalies flagged'
                    : 'Clean pre-execution profile'}
                </p>
              </div>
            </div>
            {verdict?.thresholds && (
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                <div className="rounded border border-border/60 bg-muted/30 p-1.5" title="Sensitivity profile and verdict thresholds">
                  <Gauge className="inline w-3 h-3 mr-1 text-accent" />
                  {verdict.profile ?? 'apk'} · M≥{verdict.thresholds.medium} H≥{verdict.thresholds.high}
                </div>
                {confidencePct != null && (
                  <div
                    className="rounded border border-border/60 bg-muted/30 p-1.5"
                    title="Heuristic confidence: stability of the verdict when each signal category is removed, blended with the margin to the nearest threshold. Not a calibrated probability."
                  >
                    conf {confidencePct}%
                    {verdict.score_interval && (
                      <span className="text-muted-foreground"> · [{verdict.score_interval[0]}, {verdict.score_interval[1]}]</span>
                    )}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Card 2: ML Model Prediction */}
        <Card className="border border-border/80 bg-card/90 shadow-md">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase text-muted-foreground tracking-wider">
                Random Forest ML
              </span>
              <span className={`text-[11px] font-mono px-2 py-0.5 rounded-full border font-semibold ${tone.accent}`}>
                17 features
              </span>
            </div>
          </CardHeader>
          <CardContent>
            {ml_prediction ? (
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-2xl font-bold font-mono text-foreground">
                    {(prob * 100).toFixed(1)}%
                  </div>
                  <div className="text-xs font-mono text-muted-foreground mt-0.5 flex items-center gap-1.5">
                    <span className={`w-2 h-2 rounded-full ${ml_prediction.label === 'PACKED' ? 'bg-rose-500' : 'bg-emerald-500'}`}></span>
                    Classified: <span className="font-semibold text-foreground">{ml_prediction.label}</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground">Confidence: {(ml_prediction.confidence * 100).toFixed(0)}%</p>
                </div>
                <div className="h-16 w-16 relative" aria-hidden="true">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={mlData} cx="50%" cy="50%" innerRadius={20} outerRadius={30} startAngle={90} endAngle={-270} dataKey="value" stroke="none" isAnimationActive={false}>
                        {mlData.map((entry) => (
                          <Cell key={entry.name} fill={entry.fill} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground font-mono py-3">
                {file_type === 'APK' ? 'ML classifier applies to PE binaries only.' : 'Model not loaded on the server.'}
              </p>
            )}
          </CardContent>
        </Card>

        {/* Card 3: Artifact Identity */}
        <Card className="border border-border/80 bg-card/90 shadow-md">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase text-muted-foreground tracking-wider">
                Binary Metadata
              </span>
              <span className={`text-[11px] font-mono px-2 py-0.5 rounded-full border ${tone.neutral}`}>
                {file_type === 'PE' ? pe_info?.arch ?? 'PE32' : 'Android Dalvik'}
              </span>
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-muted-foreground flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-accent" />
                Format
              </span>
              <span className="text-foreground font-semibold truncate ml-2">
                {file_type === 'APK' && apk_info ? apk_info.package_name : `${file_type} Binary`}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-muted-foreground flex items-center gap-1.5">
                <Box className="w-3.5 h-3.5 text-accent" />
                File Size
              </span>
              <span className="text-foreground">{(file_size / 1024).toFixed(1)} KB</span>
            </div>
            <div className="pt-1 border-t border-border/60 flex items-center gap-1.5 text-[11px] font-mono text-muted-foreground truncate" title={sha256}>
              <Fingerprint className="w-3.5 h-3.5 flex-shrink-0 text-accent" />
              <span className="truncate">{sha256}</span>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="summary" className="w-full">
        <TabsList className="grid h-auto w-full grid-cols-1 sm:grid-cols-3 gap-1 bg-muted/40 p-1 border border-border/80 rounded-lg">
          <TabsTrigger value="summary" className="text-xs font-mono data-[state=active]:bg-card data-[state=active]:text-accent">
            Summary & MITRE
          </TabsTrigger>
          {file_type === 'PE' && (
            <TabsTrigger value="pe-details" className="text-xs font-mono data-[state=active]:bg-card data-[state=active]:text-accent">
              PE Sections & Opcodes
            </TabsTrigger>
          )}
          {file_type === 'APK' && (
            <TabsTrigger value="apk-details" className="text-xs font-mono data-[state=active]:bg-card data-[state=active]:text-accent">
              APK Manifest & IoCs
            </TabsTrigger>
          )}
          <TabsTrigger value="intelligence" className="text-xs font-mono data-[state=active]:bg-card data-[state=active]:text-accent">
            Extracted Threat Intel
          </TabsTrigger>
        </TabsList>

        {/* Tab 1: Summary & MITRE Coverage */}
        <TabsContent value="summary" className="space-y-4 pt-3">
          <Card className="border border-border/80 bg-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-bold text-foreground flex items-center gap-2">
                <Activity className="w-4 h-4 text-accent" />
                Triggered Security Signals ({verdict?.reasons.length ?? 0})
              </CardTitle>
              <CardDescription className="text-xs">
                Deterministic indicators extracted prior to execution, with their ATT&CK technique.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {verdict && verdict.reasons.length > 0 ? (
                <ul className="space-y-2">
                  {verdict.reasons.map((r, i) => {
                    const technique = verdict.mitre_techniques[i]
                    return (
                      <li key={`${i}-${r}`} className="flex flex-wrap sm:flex-nowrap items-start gap-2.5 text-xs font-mono p-2.5 rounded bg-muted/30 border border-border/60">
                        <span className={`px-1.5 py-0.5 rounded border font-bold text-[10px] uppercase shrink-0 mt-0.5 ${tone[vTone]}`}>
                          FLAG {i + 1}
                        </span>
                        <span className="text-foreground leading-relaxed flex-1 min-w-0 break-words">{r}</span>
                        {technique?.mitre_id && (
                          <a
                            href={mitreUrl(technique.mitre_id)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className={`shrink-0 px-1.5 py-0.5 rounded border text-[10px] font-bold hover:underline ${tone.accent}`}
                            title={technique.mitre_name ?? undefined}
                          >
                            {technique.mitre_id}
                          </a>
                        )}
                      </li>
                    )
                  })}
                </ul>
              ) : (
                <div className={`text-xs font-mono flex items-center gap-2 p-3 border rounded ${tone.ok}`}>
                  <CheckCircle2 className="w-4 h-4" />
                  No anomalous evasion flags triggered for this binary.
                </div>
              )}
            </CardContent>
          </Card>

          {mitreList.length > 0 && (
            <Card className="border border-border/80 bg-card">
              <CardHeader className="pb-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <CardTitle className="text-sm font-bold text-foreground flex items-center gap-2">
                      <Layers className="w-4 h-4 text-accent" />
                      MITRE ATT&CK Alignment
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Techniques evidenced by heuristic signals and YARA rule hits.
                    </CardDescription>
                  </div>
                  <span className="text-xs font-mono text-muted-foreground">
                    {mitreList.length} Techniques Mapped
                  </span>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {mitreList.map((t) => (
                    <a
                      key={t.id}
                      href={mitreUrl(t.id)}
                      target="_blank"
                      rel="noopener noreferrer"
                      title={`Evidence: ${t.sources.join(', ')}`}
                      className="group flex items-center justify-between p-2.5 rounded border border-border/70 bg-muted/20 hover:bg-muted/50 hover:border-accent/40 transition-all text-xs font-mono"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`px-1.5 py-0.5 rounded border font-bold text-[10px] shrink-0 ${tone.accent}`}>
                          {t.id}
                        </span>
                        <span className="text-foreground truncate group-hover:text-accent transition-colors">
                          {t.name || 'View technique'}
                        </span>
                      </div>
                      <ExternalLink className="w-3.5 h-3.5 text-muted-foreground group-hover:text-accent shrink-0 ml-2" />
                    </a>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {yara_matches && yara_matches.length > 0 && (
            <Card className="border border-border/80 bg-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-bold text-foreground flex items-center gap-2">
                  <Code2 className="w-4 h-4 text-accent" />
                  YARA Signature Matches ({yara_matches.length})
                </CardTitle>
                <CardDescription className="text-xs">
                  Rule triggers from rules/*.yar (basic indicators and crypter stub heuristics).
                </CardDescription>
              </CardHeader>
              <CardContent className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead className="font-mono text-xs text-muted-foreground">Rule</TableHead>
                      <TableHead className="font-mono text-xs text-muted-foreground">Description</TableHead>
                      <TableHead className="font-mono text-xs text-muted-foreground text-right">ATT&CK</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {yara_matches.map((m) => (
                      <TableRow key={`${m.namespace ?? ''}:${m.rule}`} className="border-border/60 hover:bg-muted/30">
                        <TableCell className="font-mono text-xs text-accent font-semibold">
                          {m.rule}
                          {m.confidence && <span className="block text-[10px] font-normal text-muted-foreground">confidence: {m.confidence}</span>}
                        </TableCell>
                        <TableCell className="text-xs text-foreground font-mono">{m.description}</TableCell>
                        <TableCell className="text-right">
                          {m.mitre_id ? (
                            <a href={mitreUrl(m.mitre_id)} target="_blank" rel="noopener noreferrer" className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold hover:underline ${tone.accent}`}>
                              {m.mitre_id}
                            </a>
                          ) : (
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${tone.neutral}`}>HIT</span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Tab 2: PE Sections & Opcodes */}
        {file_type === 'PE' && (
          <TabsContent value="pe-details" className="space-y-4 pt-3">
            <Card className="border border-border/80 bg-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-bold text-foreground flex items-center gap-2">
                  <Box className="w-4 h-4 text-accent" />
                  PE Sections & Shannon Entropy
                </CardTitle>
                <CardDescription className="text-xs">
                  Sections with entropy &gt; 7.0 bits/byte are flagged as packed; sections under 256 bytes are too small to judge.
                </CardDescription>
              </CardHeader>
              <CardContent className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead className="font-mono text-xs text-muted-foreground">Section</TableHead>
                      <TableHead className="font-mono text-xs text-muted-foreground">Entropy (bits/byte)</TableHead>
                      <TableHead className="font-mono text-xs text-muted-foreground">Raw Size</TableHead>
                      <TableHead className="font-mono text-xs text-muted-foreground">Virtual Size</TableHead>
                      <TableHead className="font-mono text-xs text-muted-foreground text-right">Packed?</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {sections?.map((sec, idx) => (
                      <TableRow key={`${idx}-${sec.name}`} className="border-border/60 hover:bg-muted/30">
                        <TableCell className="font-mono text-xs font-semibold text-foreground">{sec.name || '(blank)'}</TableCell>
                        <TableCell className={`font-mono text-xs ${sec.likely_packed ? `${toneText.danger} font-bold` : 'text-foreground'}`}>
                          {formatEntropy(sec.entropy)}
                          {sec.entropy_reliable === false && <span className="ml-1 text-[10px] text-muted-foreground">(small)</span>}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{sec.raw_size} B</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{sec.virtual_size} B</TableCell>
                        <TableCell className="text-right">
                          {sec.likely_packed ? (
                            <span className={`inline-flex items-center gap-1 font-mono text-[10px] px-2 py-0.5 rounded border font-bold ${tone.danger}`}>
                              <Lock className="w-2.5 h-2.5" /> PACKED
                            </span>
                          ) : (
                            <span className={`inline-flex items-center gap-1 font-mono text-[10px] px-2 py-0.5 rounded border ${tone.neutral}`}>
                              <Unlock className="w-2.5 h-2.5" /> OK
                            </span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            {syscalls.length > 0 && (
              <Card className="border border-border/80 bg-card">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-bold text-foreground flex items-center gap-2">
                    <Zap className="w-4 h-4 text-accent" />
                    Direct Syscall & SSN-Resolution Techniques ({syscalls.length})
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Hell's Gate, Halo's Gate, TartarusGate, FreshyCalls and Heaven's Gate fingerprints in executable sections.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2 text-xs font-mono">
                    {syscalls.map((s, i) => (
                      <li key={`${i}-${s.reason}`} className="p-2 rounded bg-muted/30 border border-border/60 flex flex-wrap items-start gap-2">
                        <span className={`px-1.5 py-0.5 rounded border font-bold text-[10px] ${tone.danger}`}>
                          {s.technique ?? 'Direct syscall'}
                        </span>
                        <span className="text-foreground text-[11px] break-words">{s.reason}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="border border-border/80 bg-card">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-bold text-foreground flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-accent" />
                    Anti-Analysis Opcodes & Traps
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Timing (RDTSC), debugger traps (INT 2D, ICEBP) and VM detection (CPUID, SIDT).
                  </CardDescription>
                </CardHeader>
                <CardContent className="max-h-56 overflow-y-auto">
                  {anti_analysis && anti_analysis.opcodes.length > 0 ? (
                    <ul className="space-y-2 text-xs font-mono">
                      {anti_analysis.opcodes.map((op, i) => (
                        <li key={`${i}-${op.reason}`} className="p-2 rounded bg-muted/30 border border-border/60 flex items-start gap-2">
                          <span className="px-1.5 py-0.5 rounded bg-muted text-accent font-bold text-[10px] shrink-0">
                            {op.kind ?? op.section}
                          </span>
                          <span className="text-foreground text-[11px] break-words">{op.reason}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-muted-foreground font-mono">No anti-disassembly opcodes detected.</p>
                  )}
                </CardContent>
              </Card>

              <Card className="border border-border/80 bg-card">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-bold text-foreground flex items-center gap-2">
                    <Code2 className="w-4 h-4 text-accent" />
                    Suspicious Tool & VM Strings
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Regex automaton hits across ASCII and UTF-16LE.
                  </CardDescription>
                </CardHeader>
                <CardContent className="max-h-56 overflow-y-auto">
                  {anti_analysis && anti_analysis.strings.length > 0 ? (
                    <ul className="space-y-1.5 text-xs font-mono">
                      {anti_analysis.strings.map((str) => (
                        <li key={str.string} className="p-1.5 rounded bg-muted/30 border border-border/60 flex justify-between gap-2 text-[11px]">
                          <span className="text-accent font-bold break-all">{str.string}</span>
                          <span className="text-muted-foreground text-right">{str.category}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-muted-foreground font-mono">No analysis software strings identified.</p>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        )}

        {/* Tab 3: APK Manifest & IoCs */}
        {file_type === 'APK' && (
          <TabsContent value="apk-details" className="space-y-4 pt-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="border border-border/80 bg-card">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-bold text-foreground">Android Permissions ({apk_permissions?.length ?? 0})</CardTitle>
                  <CardDescription className="text-xs">Extracted from AndroidManifest.xml.</CardDescription>
                </CardHeader>
                <CardContent className="max-h-56 overflow-y-auto">
                  <ul className="space-y-1 text-xs font-mono">
                    {apk_permissions?.map((perm) => (
                      <li key={perm} className="p-1.5 rounded bg-muted/30 border border-border/60 text-foreground text-[11px] break-all">
                        {perm.replace('android.permission.', '')}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>

              <Card className="border border-border/80 bg-card">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-bold text-foreground">Network Endpoints ({apk_endpoints?.length ?? 0})</CardTitle>
                  <CardDescription className="text-xs">Scraped URLs and IP addresses.</CardDescription>
                </CardHeader>
                <CardContent className="max-h-56 overflow-y-auto">
                  <ul className="space-y-1 text-xs font-mono">
                    {apk_endpoints?.map((ep) => (
                      <li key={ep} className="p-1.5 rounded bg-muted/30 border border-border/60 text-accent text-[11px] truncate" title={ep}>
                        {ep}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </div>

            {apk_suspicious_apis && apk_suspicious_apis.length > 0 && (
              <Card className="border border-border/80 bg-card">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-bold text-foreground">Suspicious API Usage ({apk_suspicious_apis.length})</CardTitle>
                  <CardDescription className="text-xs">Call sites found in decompiled sources (capped at 500).</CardDescription>
                </CardHeader>
                <CardContent className="max-h-72 overflow-y-auto">
                  <ul className="space-y-1 text-xs font-mono">
                    {apk_suspicious_apis.slice(0, 200).map((hit, i) => (
                      <li key={`${i}-${hit.file}-${hit.api}`} className="p-1.5 rounded bg-muted/30 border border-border/60 text-[11px] flex flex-wrap gap-2">
                        <span className={`px-1 rounded border ${tone.warn}`}>{hit.api}</span>
                        <span className="text-muted-foreground break-all">{hit.file}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        )}

        {/* Tab 4: Threat Intelligence */}
        <TabsContent value="intelligence" className="space-y-4 pt-3">
          <Card className="border border-border/80 bg-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-bold text-foreground">Extracted Indicators of Compromise (IoCs)</CardTitle>
              <CardDescription className="text-xs">Exportable threat intelligence generated during analysis.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="p-3 rounded bg-muted/30 border border-border/60 text-xs font-mono space-y-1.5">
                <div className="text-muted-foreground uppercase text-[10px]">SHA-256 Hash:</div>
                <div className="text-accent break-all select-all">{sha256}</div>
              </div>
              <div className="p-3 rounded bg-muted/30 border border-border/60 text-xs font-mono space-y-1.5">
                <div className="text-muted-foreground uppercase text-[10px]">Triage Classification:</div>
                <div className="text-foreground">
                  {verdict?.verdict ?? 'UNKNOWN'} Risk (Score: {verdict?.score ?? 0})
                  {ml_prediction && ` • ML Model: ${ml_prediction.label} (${(ml_prediction.probability * 100).toFixed(1)}%)`}
                </div>
              </div>
              <div className="p-3 rounded bg-muted/30 border border-border/60 text-xs font-mono space-y-1.5">
                <div className="text-muted-foreground uppercase text-[10px]">Suggested Next Step:</div>
                <div className="text-foreground">
                  {isHighRisk
                    ? 'Sample demonstrates evasion or packed sections. Transfer to an isolated host-only analysis VM for unpacking and dynamic analysis.'
                    : isMediumRisk
                    ? 'Mixed indicators. Corroborate with dynamic analysis or a second profile before clearing.'
                    : 'Low threat profile under static analysis. Static triage cannot rule out runtime-only behaviour.'}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
