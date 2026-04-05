"use client"

import { useState } from "react"
import { formatDistanceToNow, format } from "date-fns"
import { FileText, ChevronDown, ChevronUp } from "lucide-react"

interface Log {
  id: string
  device_id: string
  event_type: string
  rssi: number | null
  payload: Record<string, unknown>
  message: string | null
  source_ip: string | null
  created_at: string
}

interface LogsTableProps {
  logs: Log[]
  total: number
  selectedDevice: string
  selectedEventType: string
  onDeviceChange: (value: string) => void
  onEventTypeChange: (value: string) => void
  devices: { device_id: string; name: string | null }[]
}

const eventTypes = ["all", "heartbeat", "alert", "trigger", "error", "info"]

function getEventTypeColor(type: string) {
  switch (type) {
    case "alert":
      return "bg-destructive/20 text-destructive"
    case "trigger":
      return "bg-warning/20 text-warning"
    case "error":
      return "bg-destructive/20 text-destructive"
    case "heartbeat":
      return "bg-success/20 text-success"
    case "info":
      return "bg-info/20 text-info"
    default:
      return "bg-secondary text-secondary-foreground"
  }
}

export function LogsTable({
  logs,
  total,
  selectedDevice,
  selectedEventType,
  onDeviceChange,
  onEventTypeChange,
  devices,
}: LogsTableProps) {
  const [expandedLog, setExpandedLog] = useState<string | null>(null)

  return (
    <div className="overflow-hidden">
      <div className="flex flex-col gap-6 border-b border-white/10 p-6 md:flex-row md:items-center">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-info/20 p-2">
            <FileText className="h-5 w-5 text-info" />
          </div>
          <h2 className="text-xl font-bold tracking-tight text-foreground">Event Logs</h2>
          <span className="rounded-full bg-white/5 px-3 py-1 text-xs font-bold text-muted-foreground">
            {total.toLocaleString()} Total
          </span>
        </div>
        <div className="flex flex-wrap gap-3 md:ml-auto">
          <select
            value={selectedDevice}
            onChange={(e) => onDeviceChange(e.target.value)}
            className="rounded-xl border border-white/10 bg-black/40 px-4 py-2 text-sm font-bold text-foreground focus:outline-none focus:ring-2 focus:ring-info/50 appearance-none cursor-pointer"
          >
            <option value="all">All Devices</option>
            {devices.map((device) => (
              <option key={device.device_id} value={device.device_id}>
                {device.name || device.device_id}
              </option>
            ))}
          </select>
          <select
            value={selectedEventType}
            onChange={(e) => onEventTypeChange(e.target.value)}
            className="rounded-xl border border-white/10 bg-black/40 px-4 py-2 text-sm font-bold text-foreground focus:outline-none focus:ring-2 focus:ring-info/50 appearance-none cursor-pointer"
          >
            {eventTypes.map((type) => (
              <option key={type} value={type}>
                {type === "all" ? "All Events" : type.toUpperCase()}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/5 text-left text-xs font-bold uppercase tracking-widest text-muted-foreground/60">
              <th className="px-6 py-4">Time</th>
              <th className="px-6 py-4">Device</th>
              <th className="px-6 py-4">Event</th>
              <th className="px-6 py-4">RSSI</th>
              <th className="px-6 py-4">Message</th>
              <th className="px-6 py-4">Payload</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {logs.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-6 py-12 text-center text-sm font-medium text-muted-foreground/50"
                >
                  No logs found
                </td>
              </tr>
            ) : (
              logs.map((log) => (
                <>
                  <tr
                    key={log.id}
                    className="transition-colors hover:bg-white/5 group"
                  >
                    <td className="px-6 py-4">
                      <div className="flex flex-col">
                        <span className="text-sm font-bold text-foreground">
                          {format(new Date(log.created_at), "HH:mm:ss")}
                        </span>
                        <span className="text-[10px] font-black uppercase tracking-tighter text-muted-foreground/50">
                          {formatDistanceToNow(new Date(log.created_at), {
                            addSuffix: true,
                          })}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <code className="rounded bg-black/40 px-2 py-1 font-mono text-xs font-semibold text-foreground/80">
                        {log.device_id}
                      </code>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`rounded-lg border px-2 py-1 text-[10px] font-black uppercase tracking-widest ${getEventTypeColor(log.event_type)}`}
                      >
                        {log.event_type}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs font-bold text-muted-foreground/80">
                      {log.rssi !== null ? `${log.rssi} dBm` : "—"}
                    </td>
                    <td className="max-w-xs truncate px-6 py-4 text-sm font-medium text-muted-foreground">
                      {log.message || "—"}
                    </td>
                    <td className="px-6 py-4">
                      {Object.keys(log.payload).length > 0 ? (
                        <button
                          onClick={() =>
                            setExpandedLog(
                              expandedLog === log.id ? null : log.id
                            )
                          }
                          className="flex items-center gap-1 text-xs font-bold text-info transition-colors hover:text-info/80"
                        >
                          {expandedLog === log.id ? (
                            <>
                              Hide <ChevronUp className="h-4 w-4" />
                            </>
                          ) : (
                            <>
                              View <ChevronDown className="h-4 w-4" />
                            </>
                          )}
                        </button>
                      ) : (
                        <span className="text-muted-foreground/30">—</span>
                      )}
                    </td>
                  </tr>
                  {expandedLog === log.id && (
                    <tr key={`${log.id}-payload`}>
                      <td
                        colSpan={6}
                        className="bg-black/40 px-6 py-6"
                      >
                        <pre className="overflow-x-auto rounded-xl border border-white/5 bg-black/20 p-4 text-xs font-medium text-muted-foreground/90">
                          {JSON.stringify(log.payload, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
