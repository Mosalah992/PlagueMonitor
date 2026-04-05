-- Create beacon_devices table to store registered beacon devices
CREATE TABLE IF NOT EXISTS beacon_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id TEXT UNIQUE NOT NULL,
  name TEXT,
  description TEXT,
  location TEXT,
  metadata JSONB DEFAULT '{}',
  is_active BOOLEAN DEFAULT true,
  last_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create beacon_logs table to store all beacon events
CREATE TABLE IF NOT EXISTS beacon_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('heartbeat', 'alert', 'trigger', 'error', 'info', 'custom')),
  signal_strength INTEGER,
  payload JSONB DEFAULT '{}',
  source_ip TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_beacon_logs_device_id ON beacon_logs(device_id);
CREATE INDEX IF NOT EXISTS idx_beacon_logs_event_type ON beacon_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_beacon_logs_created_at ON beacon_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_beacon_devices_device_id ON beacon_devices(device_id);
CREATE INDEX IF NOT EXISTS idx_beacon_devices_is_active ON beacon_devices(is_active);

-- Disable RLS for these tables (beacon endpoints are public for local projects)
ALTER TABLE beacon_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE beacon_logs ENABLE ROW LEVEL SECURITY;

-- Create policies to allow all operations (no auth required for beacon ingestion)
CREATE POLICY "Allow all access to beacon_devices" ON beacon_devices FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all access to beacon_logs" ON beacon_logs FOR ALL USING (true) WITH CHECK (true);
