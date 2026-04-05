"use client"

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
