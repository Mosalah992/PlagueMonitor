"use client"

import { useEffect, useState, useCallback } from "react"
import useSWR from "swr"
import { RefreshCw, Shield } from "lucide-react"
import { StatsCards } from "@/components/dashboard/stats-cards"
import { DevicesTable } from "@/components/dashboard/devices-table"
import { LogsTable } from "@/components/dashboard/logs-table"

const fetcher = (url: string) => fetch(url).then((res) => res.json())

export default function DashboardPage() {
  const [selectedAgent, setSelectedAgent] = useState("all")
  const [selectedEventType, setSelectedEventType] = useState("all")
  const [autoRefresh, setAutoRefresh] = useState(true)
 
  // Fetch stats
  const { data: statsData, mutate: mutateStats } = useSWR(
    "/api/simulation/stats",
    fetcher,
    { refreshInterval: autoRefresh ? 5000 : 0 }
  )
 
  // Fetch agents
  const { data: agentsData, mutate: mutateAgents } = useSWR(
    "/api/simulation/agents",
    fetcher,
    { refreshInterval: autoRefresh ? 5000 : 0 }
  )
 
  // Build logs URL with filters
  const logsUrl = `/api/simulation/logs?limit=50${
    selectedAgent !== "all" ? `&agent_id=${selectedAgent}` : ""
  }${selectedEventType !== "all" ? `&event_type=${selectedEventType}` : ""}`
 
  // Fetch logs
  const { data: logsData, mutate: mutateLogs } = useSWR(logsUrl, fetcher, {
    refreshInterval: autoRefresh ? 5000 : 0,
  })
 
  const handleRefresh = useCallback(() => {
    mutateStats()
    mutateAgents()
    mutateLogs()
  }, [mutateStats, mutateAgents, mutateLogs])
 
  // Handle filter changes
  useEffect(() => {
    mutateLogs()
  }, [selectedAgent, selectedEventType, mutateLogs])
 
  return (
    <div className="min-h-screen mesh-gradient">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-white/10 glass-dark">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-4">
            <div className="relative rounded-2xl bg-info/20 p-2.5 shadow-[0_0_20px_-5px_oklch(0.65_0.18_250_/_0.3)]">
              <Shield className="h-6 w-6 text-info" />
              <div className="absolute -right-0.5 -top-0.5 h-3 w-3 rounded-full border-2 border-[#0a0a0a] bg-info pulse-slow" />
            </div>
            <div>
              <h1 className="text-xl font-black tracking-tight text-foreground">
                PlagueMonitor Dashboard
              </h1>
              <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-muted-foreground/50">
                AI Epidemic Simulation & Forecasting
              </p>
            </div>
          </div>
          <div className="flex items-center gap-6">
            <label className="group flex cursor-pointer items-center gap-3 text-xs font-bold uppercase tracking-tighter text-muted-foreground/60 transition-colors hover:text-foreground">
              <div className="relative flex h-5 w-5 items-center justify-center">
                <input
                  type="checkbox"
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                  className="peer h-4 w-4 rounded-md border-white/20 bg-white/5 text-info focus:ring-info transition-all cursor-pointer"
                />
                <div className={`pointer-events-none absolute inset-0 rounded-md ring-2 ring-info/50 opacity-0 transition-opacity peer-checked:opacity-100 ${autoRefresh ? 'pulse-slow' : ''}`} />
              </div>
              Auto-refresh
            </label>
            <button
              onClick={handleRefresh}
              className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-black uppercase tracking-widest text-foreground transition-all hover:bg-white/10 active:scale-95 shadow-lg border-b-2 border-b-white/5"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${autoRefresh ? 'animate-spin-slow' : ''}`} />
              Sync
            </button>
          </div>
        </div>
      </header>
 
      {/* Main content */}
      <main className="mx-auto max-w-7xl px-6 py-10">
        <div className="flex flex-col gap-10">
          {/* Stats Cards Section */}
          <section>
             <div className="mb-4 flex items-center gap-2 px-2">
                <div className="h-1 w-8 rounded-full bg-info" />
                <h3 className="text-sm font-black uppercase tracking-widest text-foreground/70">Aggregate Metrics</h3>
             </div>
             <StatsCards stats={statsData} />
          </section>
 
          {/* Tables Section */}
          <section className="grid gap-10">
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-2 px-2">
                <div className="h-1 w-8 rounded-full bg-info" />
                <h3 className="text-sm font-black uppercase tracking-widest text-foreground/70">Population Tracking</h3>
              </div>
              <DevicesTable agents={agentsData?.agents || []} />
            </div>
 
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-2 px-2">
                <div className="h-1 w-8 rounded-full bg-info" />
                <h3 className="text-sm font-black uppercase tracking-widest text-foreground/70">Encounter Telemetry</h3>
              </div>
              <LogsTable
                logs={logsData?.logs || []}
                total={logsData?.total || 0}
                selectedAgent={selectedAgent}
                selectedEventType={selectedEventType}
                onAgentChange={setSelectedAgent}
                onEventTypeChange={setSelectedEventType}
                agents={
                  agentsData?.agents?.map(
                    (a: { agent_id: string; name: string | null }) => ({
                      agent_id: a.agent_id,
                      name: a.name,
                    })
                  ) || []
                }
              />
            </div>
          </section>
        </div>
      </main>
    </div>
  )
}
