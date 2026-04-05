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
    <div className="min-h-screen">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-white/10 glass-dark">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-4">
            <div className="rounded-lg bg-info/20 p-2">
              <Shield className="h-6 w-6 text-info" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground">
                PlagueMonitor Dashboard
              </h1>
              <p className="text-xs font-medium text-muted-foreground/70">
                Epidemic simulation logging and monitoring
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <label className="flex cursor-pointer items-center gap-3 text-sm font-medium text-muted-foreground/80 transition-colors hover:text-foreground">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="h-4 w-4 rounded border-white/20 bg-white/5 text-info focus:ring-info"
              />
              Auto-refresh
            </label>
            <button
              onClick={handleRefresh}
              className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-bold text-foreground transition-all hover:bg-white/10 active:scale-95"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
        </div>
      </header>
 
      {/* Main content */}
      <main className="mx-auto max-w-7xl px-6 py-8">
        <div className="flex flex-col gap-8">
          {/* Stats Cards */}
          <div className="rounded-2xl border border-white/5 glass p-1">
             <StatsCards stats={statsData} />
          </div>
 
          {/* Tables Section */}
          <div className="grid gap-8">
            <div className="rounded-2xl border border-white/5 glass p-6 shadow-xl">
              <DevicesTable agents={agentsData?.agents || []} />
            </div>
 
            <div className="rounded-2xl border border-white/5 glass p-6 shadow-xl">
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
          </div>
        </div>
      </main>
    </div>
  )
}
