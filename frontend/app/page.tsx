import Link from "next/link"
import { Shield, Radio, FileText, ArrowRight } from "lucide-react"

export default function HomePage() {
  return (
    <div className="min-h-screen">
      <div className="mx-auto max-w-4xl px-4 py-16">
        {/* Hero */}
        <div className="mb-12 text-center">
          <div className="mb-6 flex justify-center">
            <div className="rounded-full bg-info/20 p-6 shadow-[0_0_50px_-12px_rgba(var(--info),0.5)]">
              <Shield className="h-16 w-16 text-info" />
            </div>
          </div>
          <h1 className="mb-4 text-5xl font-extrabold tracking-tight text-foreground">
            PlagueMonitor
          </h1>
          <p className="mb-8 text-xl text-muted-foreground/80">
            AI Epidemic Simulation & Forecasting Platform
          </p>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 rounded-xl bg-primary px-8 py-4 font-bold text-primary-foreground transition-all hover:scale-105 hover:bg-primary/90 shadow-lg shadow-primary/20"
          >
            Open Simulation Dashboard
            <ArrowRight className="h-5 w-5" />
          </Link>
        </div>

        {/* API Documentation */}
        <div className="rounded-2xl border border-white/10 glass p-8 shadow-2xl">
          <h2 className="mb-8 text-2xl font-bold tracking-tight text-foreground">
            Simulation API
          </h2>

          <div className="space-y-8">
            {/* Post Infection Event */}
            <div className="rounded-xl border border-white/5 glass-dark p-6 transition-all hover:border-white/10">
              <div className="mb-3 flex items-center gap-3">
                <Radio className="h-5 w-5 text-info" />
                <code className="rounded bg-black/40 px-2 py-1 font-mono text-sm font-semibold text-info">
                  POST /api/simulation/event
                </code>
              </div>
              <p className="mb-4 text-sm text-muted-foreground">
                Register a new infection event in current run.
              </p>
              <pre className="overflow-x-auto rounded-lg bg-black/50 p-4 text-xs text-muted-foreground/90 border border-white/5">
{`{
  "run_id": "uuid-v4",           // required
  "agent_id": "agent-001",       // required
  "target_id": "agent-002",      // optional (infected agent)
  "location": [12.5, 45.3],      // optional [x, y]
  "metadata": { ... }             // optional JSON
}`}
              </pre>
            </div>

            {/* Update Agent State */}
            <div className="rounded-xl border border-white/5 glass-dark p-6 transition-all hover:border-white/10">
              <div className="mb-3 flex items-center gap-3">
                <FileText className="h-5 w-5 text-success" />
                <code className="rounded bg-black/40 px-2 py-1 font-mono text-sm font-semibold text-success">
                  POST /api/simulation/agent
                </code>
              </div>
              <p className="mb-4 text-sm text-muted-foreground">
                Update high-fidelity agent state.
              </p>
              <pre className="overflow-x-auto rounded-lg bg-black/50 p-4 text-xs text-muted-foreground/90 border border-white/5">
{`{
  "agent_id": "agent-001",       // required
  "status": "infected",          // susceptible, infected, recovered, dead
  "viral_load": 0.85,            // optional: 0.0 to 1.0
  "coordinates": [x, y],         // optional
  "message": "Encounter event"   // optional
}`}
              </pre>
            </div>

            {/* Get Logs */}
            <div className="rounded-xl border border-white/5 glass-dark p-6 transition-all hover:border-white/10">
              <div className="mb-3 flex items-center gap-3">
                <FileText className="h-5 w-5 text-chart-3" />
                <code className="rounded bg-black/40 px-2 py-1 font-mono text-sm font-semibold text-chart-3">
                  GET /api/simulation/logs
                </code>
              </div>
              <p className="mb-4 text-sm text-muted-foreground">
                Retrieve real-time simulation event stream.
              </p>
              <pre className="overflow-x-auto rounded-lg bg-black/50 p-4 text-xs text-muted-foreground/90 border border-white/5">
{`Query parameters:
  run_id       - filter by simulation run
  agent_id     - filter by specific agent
  limit        - max results (default: 100)
  offset       - pagination offset`}
              </pre>
            </div>
          </div>
        </div>

        {/* Example Usage */}
        <div className="mt-8 rounded-2xl border border-white/10 glass p-8 shadow-2xl">
          <h2 className="mb-6 text-2xl font-bold tracking-tight text-foreground">
            Example: Register Infection
          </h2>
          <pre className="overflow-x-auto rounded-xl bg-black/50 p-5 text-xs text-muted-foreground/90 border border-white/5">
{`curl -X POST ${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/simulation/event \\
  -H "Content-Type: application/json" \\
  -d '{
    "run_id": "default-run",
    "agent_id": "agent-001",
    "target_id": "agent-002",
    "metadata": {
      "variant": "delta",
      "probability": 0.95
    }
  }'`}
          </pre>
        </div>
      </div>
    </div>
  )
}
