import Link from "next/link"
import { Shield, Radio, FileText, ArrowRight } from "lucide-react"

export default function HomePage() {
  return (
    <div className="min-h-screen mesh-gradient selection:bg-info/30 selection:text-white">
      <div className="mx-auto max-w-5xl px-6 py-24 md:py-32">
        {/* Hero Section */}
        <div className="relative mb-24 text-center">
          {/* Background Glows */}
          <div className="absolute left-1/2 top-1/2 -z-10 h-[400px] w-[400px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-info/10 blur-[120px]" />
          <div className="absolute left-1/2 top-1/2 -z-10 h-[200px] w-[200px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-info/20 blur-[60px]" />
          
          <div className="mb-10 flex justify-center">
            <div className="group relative rounded-[2.5rem] bg-white/5 p-8 shadow-2xl transition-all duration-500 hover:scale-110 hover:shadow-info/20">
              <Shield className="h-20 w-20 text-info" />
              <div className="absolute inset-0 rounded-[2.5rem] bg-info/20 blur-2xl opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
          </div>
          
          <div className="inline-flex items-center gap-2 rounded-full bg-white/5 border border-white/5 px-4 py-1.5 mb-6">
            <div className="h-2 w-2 rounded-full bg-info pulse-slow" />
            <span className="text-[10px] font-black uppercase tracking-[0.3em] text-info">v2.0 High-Fidelity</span>
          </div>

          <h1 className="mb-6 text-6xl font-black tracking-tighter text-foreground md:text-8xl">
            Plague<span className="text-info">Monitor</span>
          </h1>
          <p className="mx-auto mb-10 max-w-2xl text-lg font-medium text-muted-foreground/80 md:text-xl">
            A state-of-the-art AI-driven platform for high-fidelity epidemic simulation, transmission forecasting, and real-time intervention modeling.
          </p>
          
          <div className="flex flex-col items-center justify-center gap-4 sm:flex-row">
            <Link
              href="/dashboard"
              className="group relative flex items-center gap-3 rounded-2xl bg-foreground px-10 py-5 font-black uppercase tracking-widest text-background transition-all hover:scale-105 active:scale-95 shadow-[0_20px_50px_-12px_rgba(255,255,255,0.15)]"
            >
              Enter Simulation
              <ArrowRight className="h-5 w-5 transition-transform group-hover:translate-x-1" />
            </Link>
            <button className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/5 px-10 py-5 font-black uppercase tracking-widest text-foreground transition-all hover:bg-white/10 active:scale-95">
              Documentation
            </button>
          </div>
        </div>

        {/* API Documentation Section */}
        <div className="grid gap-8 md:grid-cols-1">
          <div className="rounded-[3rem] border border-white/10 glass p-8 md:p-12 shadow-2xl overflow-hidden relative group">
            <div className="absolute -right-20 -top-20 h-64 w-64 rounded-full bg-info/5 blur-3xl transition-opacity group-hover:opacity-20" />
            
            <div className="mb-12 flex items-center justify-between">
              <div>
                <h2 className="text-3xl font-black tracking-tighter text-foreground">
                  Simulation API
                </h2>
                <p className="text-sm font-medium text-muted-foreground/60">Professional integration layer for runtime engines</p>
              </div>
              <div className="hidden items-center gap-2 rounded-xl border border-white/10 bg-black/40 px-4 py-2 sm:flex">
                <div className="h-2 w-2 rounded-full bg-success" />
                <span className="text-[10px] font-black uppercase tracking-widest text-success">API Status: Ready</span>
              </div>
            </div>

            <div className="grid gap-8 lg:grid-cols-2">
              <div className="space-y-8">
                {/* Endpoint 1 */}
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <div className="rounded-lg bg-info/10 p-2 text-info border border-info/20">
                       <Radio className="h-4 w-4" />
                    </div>
                    <code className="text-sm font-black text-foreground">POST /api/simulation/event</code>
                  </div>
                  <p className="text-sm text-muted-foreground/80 leading-relaxed">
                    Register a new infection event globally or between specific agents. Triggers immediate re-calculation of transmission vectors.
                  </p>
                  <div className="rounded-2xl border border-white/5 bg-black/40 p-5 font-mono text-[11px] text-muted-foreground/90 shadow-inner">
                    <pre>{`{
  "run_id": "uuid-v4",
  "agent_id": "agent-001",
  "target_id": "agent-002",
  "metadata": { "variant": "delta" }
}`}</pre>
                  </div>
                </div>

                {/* Endpoint 2 */}
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <div className="rounded-lg bg-success/10 p-2 text-success border border-success/20">
                       <FileText className="h-4 w-4" />
                    </div>
                    <code className="text-sm font-black text-foreground">POST /api/simulation/agent</code>
                  </div>
                  <p className="text-sm text-muted-foreground/80 leading-relaxed">
                    Update high-fidelity agent attributes including viral load, movement coordinates, and clinical state transitions.
                  </p>
                  <div className="rounded-2xl border border-white/5 bg-black/40 p-5 font-mono text-[11px] text-muted-foreground/90 shadow-inner">
                    <pre>{`{
  "agent_id": "agent-001",
  "status": "infected",
  "viral_load": 0.85,
  "coordinates": [x, y]
}`}</pre>
                  </div>
                </div>
              </div>

              {/* Quick Start / Curl */}
              <div className="flex flex-col gap-6 lg:border-l lg:border-white/5 lg:pl-8">
                <div>
                   <h3 className="mb-4 text-xs font-black uppercase tracking-widest text-foreground/50">Quick Start (cURL)</h3>
                   <div className="group relative">
                      <pre className="overflow-x-auto rounded-3xl border border-white/10 bg-black/60 p-6 font-mono text-xs text-info/90 leading-relaxed shadow-2xl">
{`curl -X POST http://localhost:8001/api/simulation/event \\
  -H "Content-Type: application/json" \\
  -d '{
    "run_id": "default",
    "agent_id": "S_01",
    "target_id": "T_05",
    "metadata": {
      "variant": "omicron",
      "p": 0.92
    }
  }'`}
                      </pre>
                      <button className="absolute right-4 top-4 rounded-xl bg-white/5 px-3 py-1.5 text-[10px] font-black uppercase text-muted-foreground hover:bg-white/10 opacity-0 group-hover:opacity-100 transition-opacity">Copy</button>
                   </div>
                </div>
                <div className="rounded-2xl bg-white/5 p-5 border border-white/5">
                   <p className="text-[11px] font-medium leading-relaxed text-muted-foreground/70 italic">
                     "The high-fidelity runtime expects agent IDs to be consistent within a single 'run_id' context. Ensure the backend orchestrator (Port 8001) is active for real-time telemetry fanout."
                   </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
