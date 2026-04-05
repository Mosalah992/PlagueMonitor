import { NextResponse } from "next/server"

export async function GET() {
  try {
    // 1. Get latest run
    const runsRes = await fetch("http://localhost:8001/api/runs", { cache: "no-store" })
    const runs = await runsRes.json()
    
    if (!runs || runs.length === 0) {
      return NextResponse.json({ logs: [], total: 0 })
    }

    const latestRun = runs[0]
    
    // 2. Get events for this run
    const eventsRes = await fetch(`http://localhost:8001/api/runs/${latestRun.id}/events?limit=100`, { cache: "no-store" })
    const events = await eventsRes.json()

    return NextResponse.json({ 
      logs: events, 
      total: events.length 
    })
  } catch (err) {
    console.error("Simulation events error:", err)
    return NextResponse.json({ error: "Backend unreachable" }, { status: 503 })
  }
}
