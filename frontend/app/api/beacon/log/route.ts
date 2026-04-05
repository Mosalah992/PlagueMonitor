import { createClient } from "@/lib/supabase/server"
import { NextRequest, NextResponse } from "next/server"

function normalizePayload(payload: unknown, message: string | null) {
  const basePayload =
    typeof payload === "object" && payload !== null
      ? { ...(payload as Record<string, unknown>) }
      : payload
        ? { raw: payload }
        : {}

  if (message && typeof basePayload === "object" && basePayload !== null && !("message" in basePayload)) {
    ;(basePayload as Record<string, unknown>).message = message
  }

  return basePayload
}

function normalizeLogRecord(record: Record<string, unknown>) {
  const payload =
    typeof record.payload === "object" && record.payload !== null
      ? (record.payload as Record<string, unknown>)
      : {}

  return {
    id: record.id,
    device_id: record.device_id,
    event_type: record.event_type,
    rssi: record.signal_strength ?? null,
    payload,
    message: typeof payload.message === "string" ? payload.message : null,
    source_ip: record.source_ip ?? null,
    created_at: record.created_at,
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { device_id, event_type, rssi, payload, message } = body

    if (!device_id) {
      return NextResponse.json(
        { error: "device_id is required" },
        { status: 400 }
      )
    }

    const supabase = await createClient()

    // Get source IP and user agent for audit
    const source_ip = request.headers.get("x-forwarded-for")?.split(",")[0] || 
                      request.headers.get("x-real-ip") || 
                      "unknown"
    const user_agent = request.headers.get("user-agent") || null

    // Insert the log entry
    const { data: logData, error: logError } = await supabase
      .from("beacon_logs")
      .insert({
        device_id,
        event_type: event_type || "heartbeat",
        signal_strength: rssi || null,
        payload: normalizePayload(payload, message || null),
        source_ip,
        user_agent,
      })
      .select()
      .single()

    if (logError) {
      console.error("Error inserting log:", logError)
      return NextResponse.json(
        { error: "Failed to insert log" },
        { status: 500 }
      )
    }

    // Update device last_seen timestamp
    await supabase
      .from("beacon_devices")
      .update({
        last_seen_at: new Date().toISOString(),
        is_active: true,
        updated_at: new Date().toISOString(),
      })
      .eq("device_id", device_id)

    return NextResponse.json({ success: true, log: normalizeLogRecord(logData) })
  } catch (err) {
    console.error("Log endpoint error:", err)
    return NextResponse.json(
      { error: "Invalid request body" },
      { status: 400 }
    )
  }
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const device_id = searchParams.get("device_id")
    const event_type = searchParams.get("event_type")
    const limit = parseInt(searchParams.get("limit") || "100")
    const offset = parseInt(searchParams.get("offset") || "0")

    const supabase = await createClient()

    let query = supabase
      .from("beacon_logs")
      .select("*", { count: "exact" })
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1)

    if (device_id) {
      query = query.eq("device_id", device_id)
    }

    if (event_type) {
      query = query.eq("event_type", event_type)
    }

    const { data, error, count } = await query

    if (error) {
      console.error("Error fetching logs:", error)
      return NextResponse.json(
        { error: "Failed to fetch logs" },
        { status: 500 }
      )
    }

    return NextResponse.json({
      logs: (data || []).map((record) => normalizeLogRecord(record)),
      total: count,
    })
  } catch (err) {
    console.error("Get logs error:", err)
    return NextResponse.json(
      { error: "Failed to fetch logs" },
      { status: 500 }
    )
  }
}
