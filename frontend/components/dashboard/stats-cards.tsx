"use client"

import { Radio, Activity, AlertTriangle, Clock } from "lucide-react"

interface StatsCardsProps {
  stats: {
    totalDevices: number
    activeDevices: number
    totalLogs: number
    recentLogs: number
    alertCount: number
  } | null
}

export function StatsCards({ stats }: StatsCardsProps) {
  const cards = [
    {
      label: "Total Devices",
      value: stats?.totalDevices ?? 0,
      icon: Radio,
      color: "text-info",
    },
    {
      label: "Active (5min)",
      value: stats?.activeDevices ?? 0,
      icon: Activity,
      color: "text-success",
    },
    {
      label: "Total Logs",
      value: stats?.totalLogs ?? 0,
      icon: Clock,
      color: "text-muted-foreground",
    },
    {
      label: "Logs (1hr)",
      value: stats?.recentLogs ?? 0,
      icon: Clock,
      color: "text-chart-3",
    },
    {
      label: "Alerts",
      value: stats?.alertCount ?? 0,
      icon: AlertTriangle,
      color: "text-destructive",
    },
  ]

  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5 p-4">
      {cards.map((card) => (
        <div
          key={card.label}
          className="flex flex-col gap-3 rounded-xl border border-white/5 glass p-5 transition-all hover:scale-[1.02] hover:border-white/10"
        >
          <div className="flex items-center gap-3">
            <div className={`rounded-lg bg-current/10 p-2 ${card.color}`}>
              <card.icon className="h-5 w-5" />
            </div>
            <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground/70">
              {card.label}
            </span>
          </div>
          <span className="text-3xl font-black tabular-nums tracking-tight text-foreground">
            {card.value.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  )
}
