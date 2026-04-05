import { createClient } from "@/lib/supabase/server"
import { NextResponse } from "next/server"

export async function GET() {
  try {
    const supabase = await createClient()

    // Get total devices
    const { count: totalDevices } = await supabase
      .from("beacon_devices")
      .select("*", { count: "exact", head: true })

    // Get active devices (seen in last 5 minutes)
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString()
    const { count: activeDevices } = await supabase
      .from("beacon_devices")
      .select("*", { count: "exact", head: true })
      .eq("is_active", true)
      .gte("last_seen_at", fiveMinutesAgo)

    // Get total logs
    const { count: totalLogs } = await supabase
      .from("beacon_logs")
      .select("*", { count: "exact", head: true })

    // Get logs in last hour
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString()
    const { count: recentLogs } = await supabase
      .from("beacon_logs")
      .select("*", { count: "exact", head: true })
      .gte("created_at", oneHourAgo)

    // Get alert count (events that are alerts or triggers)
    const { count: alertCount } = await supabase
      .from("beacon_logs")
      .select("*", { count: "exact", head: true })
      .in("event_type", ["alert", "trigger", "error"])

    // Get event type breakdown
    const { data: eventBreakdown } = await supabase
      .from("beacon_logs")
      .select("event_type")

    const eventCounts: Record<string, number> = {}
    eventBreakdown?.forEach((log) => {
      eventCounts[log.event_type] = (eventCounts[log.event_type] || 0) + 1
    })

    return NextResponse.json({
      totalDevices: totalDevices || 0,
      activeDevices: activeDevices || 0,
      totalLogs: totalLogs || 0,
      recentLogs: recentLogs || 0,
      alertCount: alertCount || 0,
      eventBreakdown: eventCounts,
    })
  } catch (err) {
    console.error("Stats endpoint error:", err)
    return NextResponse.json(
      { error: "Failed to fetch stats" },
      { status: 500 }
    )
  }
}
