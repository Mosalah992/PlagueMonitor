"use client"

import { Users, Activity, AlertTriangle, CheckCircle, Shield } from "lucide-react"

interface StatsCardsProps {
  stats: {
    totalAgents: number
    infectedAgents: number
    exposedAgents: number
    recoveredAgents: number
    healthyAgents: number
    totalEvents: number
  } | null
}

export function StatsCards({ stats }: StatsCardsProps) {
  const cards = [
    {
      label: "Total Population",
      value: stats?.totalAgents ?? 0,
      icon: Users,
      color: "text-info",
    },
    {
      label: "Infected",
      value: stats?.infectedAgents ?? 0,
      icon: AlertTriangle,
      color: "text-destructive",
    },
    {
      label: "Exposed",
      value: stats?.exposedAgents ?? 0,
      icon: Activity,
      color: "text-amber-500",
    },
    {
      label: "Recovered",
      value: stats?.recoveredAgents ?? 0,
      icon: CheckCircle,
      color: "text-success",
    },
    {
      label: "Healthy",
      value: stats?.healthyAgents ?? 0,
      icon: Shield,
      color: "text-chart-3",
    },
  ]

  return (
    <div className="grid grid-cols-1 gap-6 p-6 sm:grid-cols-2 lg:grid-cols-5">
      {cards.map((card) => (
        <div
          key={card.label}
          className="group relative flex flex-col gap-4 rounded-3xl glass p-6 transition-all duration-300 hover:scale-[1.03] hover:shadow-[0_20px_50px_-12px_rgba(0,0,0,0.5)]"
        >
          {/* Accent Glow */}
          <div className={`absolute -right-4 -top-4 h-24 w-24 rounded-full opacity-0 blur-3xl transition-opacity duration-500 group-hover:opacity-20 ${card.color.replace('text-', 'bg-')}`} />
          
          <div className="flex items-center justify-between">
            <div className={`relative rounded-2xl bg-white/5 p-3 shadow-inner ${card.color}`}>
              <card.icon className="h-6 w-6" />
              {/* Icon Pulse Glow */}
              <div className={`absolute inset-0 rounded-2xl blur-md opacity-40 group-hover:opacity-70 transition-opacity ${card.color.replace('text-', 'bg-')}`} />
            </div>
            <span className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/50">
              Live Telemetry
            </span>
          </div>

          <div className="flex flex-col gap-1">
            <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground/70">
              {card.label}
            </span>
            <span className="text-4xl font-black tabular-nums tracking-tighter text-foreground">
              {card.value.toLocaleString()}
            </span>
          </div>
        </div>
      ))}
    </div>
  )
}
