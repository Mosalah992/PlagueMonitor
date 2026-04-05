import { NextResponse } from "next/server"

export async function GET() {
  try {
    // 1. Get runs
    const runsRes = await fetch("http://localhost:8001/api/runs", { cache: "no-store" })
    const runs = await runsRes.json()
    
    if (!runs || runs.length === 0) {
      return NextResponse.json({
        totalAgents: 0,
        infectedAgents: 0,
        totalEvents: 0,
        activeRuns: 0,
        healthyAgents: 0
      })
    }

    const latestRun = runs[0]
    
    // 2. Get latest snapshot for this run
    const snapRes = await fetch(`http://localhost:8001/api/runs/${latestRun.id}/snapshots?limit=1`, { cache: "no-store" })
    const snapshots = await snapRes.json()
    const latestSnap = snapshots[0] || {}

    return NextResponse.json({
      totalAgents: latestSnap.total_agents || latestRun.total_agents || 0,
      infectedAgents: latestSnap.infected_count || latestRun.infected_agents || 0,
      totalEvents: latestSnap.event_count || 0,
      recoveredAgents: latestSnap.recovered_count || 0,
      exposedAgents: latestSnap.exposed_count || 0,
      healthyAgents: latestSnap.healthy_count || 0
    })
  } catch (err) {
    console.error("Simulation stats error:", err)
    return NextResponse.json({ error: "Backend unreachable" }, { status: 503 })
  }
}
