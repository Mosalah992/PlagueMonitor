import { NextResponse } from "next/server"

export async function GET() {
  try {
    // 1. Get latest run
    const runsRes = await fetch("http://localhost:8001/api/runs", { cache: "no-store" })
    const runs = await runsRes.json()
    
    if (!runs || runs.length === 0) {
      return NextResponse.json({ agents: [] })
    }

    const latestRun = runs[0]
    
    // 2. Get agents for this run
    const agentsRes = await fetch(`http://localhost:8001/api/runs/${latestRun.id}/agents`, { cache: "no-store" })
    const agents = await agentsRes.json()

    return NextResponse.json({ agents })
  } catch (err) {
    console.error("Simulation agents error:", err)
    return NextResponse.json({ error: "Backend unreachable" }, { status: 503 })
  }
}
