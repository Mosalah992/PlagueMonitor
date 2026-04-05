"use client"

import { formatDistanceToNow } from "date-fns"
import { Circle, Radio } from "lucide-react"

interface Device {
  id: string
  device_id: string
  name: string | null
  type: string
  location: string | null
  status: string
  last_seen: string
  metadata: Record<string, unknown>
  created_at: string
}

interface DevicesTableProps {
  devices: Device[]
}

export function DevicesTable({ devices }: DevicesTableProps) {
  const isActive = (lastSeen: string) => {
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000)
    return new Date(lastSeen) > fiveMinutesAgo
  }

  return (
    <div className="overflow-hidden">
      <div className="flex items-center gap-3 border-b border-white/10 p-6">
        <div className="rounded-lg bg-info/20 p-2">
          <Radio className="h-5 w-5 text-info" />
        </div>
        <h2 className="text-xl font-bold tracking-tight text-foreground">Registered Devices</h2>
        <span className="ml-auto rounded-full bg-white/5 px-3 py-1 text-xs font-bold text-muted-foreground">
          {devices.length} Total
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/5 text-left text-xs font-bold uppercase tracking-widest text-muted-foreground/60">
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4">Device ID</th>
              <th className="px-6 py-4">Name</th>
              <th className="px-6 py-4">Type</th>
              <th className="px-6 py-4">Location</th>
              <th className="px-6 py-4">Last Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {devices.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-6 py-12 text-center text-sm font-medium text-muted-foreground/50"
                >
                  No devices registered yet
                </td>
              </tr>
            ) : (
              devices.map((device) => (
                <tr
                  key={device.id}
                  className="transition-colors hover:bg-white/5"
                >
                  <td className="px-6 py-4">
                    <div className="flex items-center">
                      <div className={`h-2.5 w-2.5 rounded-full ${
                        isActive(device.last_seen)
                          ? "bg-success shadow-[0_0_10px_rgba(var(--success),0.5)]"
                          : "bg-muted-foreground/30"
                      }`} />
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <code className="rounded bg-black/40 px-2 py-1 font-mono text-sm font-semibold text-foreground">
                      {device.device_id}
                    </code>
                  </td>
                  <td className="px-6 py-4 text-sm font-bold text-foreground">
                    {device.name || "—"}
                  </td>
                  <td className="px-6 py-4">
                    <span className="rounded-lg bg-info/10 px-2 py-1 text-xs font-bold text-info border border-info/20">
                      {device.type}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm font-medium text-muted-foreground">
                    {device.location || "—"}
                  </td>
                  <td className="px-6 py-4 text-xs font-bold text-muted-foreground/80">
                    {formatDistanceToNow(new Date(device.last_seen), {
                      addSuffix: true,
                    })}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
