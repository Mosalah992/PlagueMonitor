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
            Beacon Monitor
          </h1>
          <p className="mb-8 text-xl text-muted-foreground/80">
            A high-fidelity orchestrator for security beacon data and 
            real-time epidemic simulation telemetry.
          </p>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 rounded-xl bg-primary px-8 py-4 font-bold text-primary-foreground transition-all hover:scale-105 hover:bg-primary/90 shadow-lg shadow-primary/20"
          >
            Open Dashboard
            <ArrowRight className="h-5 w-5" />
          </Link>
        </div>

        {/* API Documentation */}
        <div className="rounded-2xl border border-white/10 glass p-8 shadow-2xl">
          <h2 className="mb-8 text-2xl font-bold tracking-tight text-foreground">
            API Endpoints
          </h2>

          <div className="space-y-8">
            {/* Register Device */}
            <div className="rounded-xl border border-white/5 glass-dark p-6 transition-all hover:border-white/10">
              <div className="mb-3 flex items-center gap-3">
                <Radio className="h-5 w-5 text-info" />
                <code className="rounded bg-black/40 px-2 py-1 font-mono text-sm font-semibold text-info">
                  POST /api/beacon/register
                </code>
              </div>
              <p className="mb-4 text-sm text-muted-foreground">
                Register or update a beacon device.
              </p>
              <pre className="overflow-x-auto rounded-lg bg-black/50 p-4 text-xs text-muted-foreground/90 border border-white/5">
{`{
  "device_id": "beacon-001",      // required
  "name": "Front Door Sensor",    // optional
  "type": "motion",               // optional, default: "unknown"
  "location": "Main Entrance",    // optional
  "metadata": { ... }             // optional JSON
}`}
              </pre>
            </div>

            {/* Log Event */}
            <div className="rounded-xl border border-white/5 glass-dark p-6 transition-all hover:border-white/10">
              <div className="mb-3 flex items-center gap-3">
                <FileText className="h-5 w-5 text-success" />
                <code className="rounded bg-black/40 px-2 py-1 font-mono text-sm font-semibold text-success">
                  POST /api/beacon/log
                </code>
              </div>
              <p className="mb-4 text-sm text-muted-foreground">
                Log a beacon event (heartbeat, alert, trigger, etc.).
              </p>
              <pre className="overflow-x-auto rounded-lg bg-black/50 p-4 text-xs text-muted-foreground/90 border border-white/5">
{`{
  "device_id": "beacon-001",      // required
  "event_type": "heartbeat",      // optional: heartbeat, alert, trigger, error, info
  "rssi": -65,                    // optional: signal strength in dBm
  "payload": { ... },             // optional: custom JSON data
  "message": "Motion detected"    // optional: log message
}`}
              </pre>
            </div>

            {/* Get Logs */}
            <div className="rounded-xl border border-white/5 glass-dark p-6 transition-all hover:border-white/10">
              <div className="mb-3 flex items-center gap-3">
                <FileText className="h-5 w-5 text-chart-3" />
                <code className="rounded bg-black/40 px-2 py-1 font-mono text-sm font-semibold text-chart-3">
                  GET /api/beacon/log
                </code>
              </div>
              <p className="mb-4 text-sm text-muted-foreground">
                Retrieve beacon logs with optional filtering.
              </p>
              <pre className="overflow-x-auto rounded-lg bg-black/50 p-4 text-xs text-muted-foreground/90 border border-white/5">
{`Query parameters:
  device_id    - filter by device
  event_type   - filter by event type
  limit        - max results (default: 100)
  offset       - pagination offset`}
              </pre>
            </div>
          </div>
        </div>

        {/* Example Usage */}
        <div className="mt-8 rounded-2xl border border-white/10 glass p-8 shadow-2xl">
          <h2 className="mb-6 text-2xl font-bold tracking-tight text-foreground">
            Example: Send a Beacon Log
          </h2>
          <pre className="overflow-x-auto rounded-xl bg-black/50 p-5 text-xs text-muted-foreground/90 border border-white/5">
{`curl -X POST ${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3001'}/api/beacon/log \\
  -H "Content-Type: application/json" \\
  -d '{
    "device_id": "beacon-001",
    "event_type": "alert",
    "rssi": -72,
    "message": "Motion detected in zone A",
    "payload": {
      "zone": "A",
      "confidence": 0.95
    }
  }'`}
          </pre>
        </div>
      </div>
    </div>
      </div>
    </div>
  )
}
