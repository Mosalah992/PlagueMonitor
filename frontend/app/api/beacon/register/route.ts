import { createClient } from "@/lib/supabase/server"
import { NextRequest, NextResponse } from "next/server"

function normalizeDeviceRecord(record: Record<string, unknown>) {
  const metadata =
    typeof record.metadata === "object" && record.metadata !== null
      ? (record.metadata as Record<string, unknown>)
      : {}

  return {
    id: record.id,
    device_id: record.device_id,
    name: record.name ?? null,
    type:
      typeof metadata.device_type === "string" && metadata.device_type
        ? metadata.device_type
        : "unknown",
    location: record.location ?? null,
    status: record.is_active === false ? "inactive" : "active",
    last_seen:
      record.last_seen_at ??
      record.updated_at ??
      record.created_at ??
      new Date().toISOString(),
    metadata,
    created_at: record.created_at,
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { device_id, name, type, location, metadata } = body

    if (!device_id) {
      return NextResponse.json(
        { error: "device_id is required" },
        { status: 400 }
      )
    }

    const supabase = await createClient()

    const { data, error } = await supabase
      .from("beacon_devices")
      .upsert(
        {
          device_id,
          name: name || null,
          location: location || null,
          description: null,
          metadata: {
            ...(typeof metadata === "object" && metadata !== null ? metadata : {}),
            device_type: type || "unknown",
          },
          last_seen_at: new Date().toISOString(),
          is_active: true,
          updated_at: new Date().toISOString(),
        },
        { onConflict: "device_id" }
      )
      .select()
      .single()

    if (error) {
      console.error("Error registering device:", error)
      return NextResponse.json(
        { error: "Failed to register device" },
        { status: 500 }
      )
    }

    return NextResponse.json({ success: true, device: normalizeDeviceRecord(data) })
  } catch (err) {
    console.error("Register endpoint error:", err)
    return NextResponse.json(
      { error: "Invalid request body" },
      { status: 400 }
    )
  }
}

export async function GET() {
  try {
    const supabase = await createClient()

    const { data, error } = await supabase
      .from("beacon_devices")
      .select("*")
      .order("last_seen_at", { ascending: false })

    if (error) {
      console.error("Error fetching devices:", error)
      return NextResponse.json(
        { error: "Failed to fetch devices" },
        { status: 500 }
      )
    }

    return NextResponse.json({
      devices: (data || []).map((record) => normalizeDeviceRecord(record)),
    })
  } catch (err) {
    console.error("Get devices error:", err)
    return NextResponse.json(
      { error: "Failed to fetch devices" },
      { status: 500 }
    )
  }
}
