/**
 * Telemetry event and evidence types matching backend src.api.schemas.events
 */

export type EventSource = "cloudtrail" | "vpc_flow" | "config" | "system";

export interface TelemetryEventResponse {
  event_id: string;
  timestamp: string;
  source: EventSource;
  action: string;
  actor?: string | null;
  resource_id?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  raw_record_id?: string | null;
  details: Record<string, any>;
  raw_payload?: Record<string, any> | null;
}

export interface EventListResponse {
  total: number;
  items: TelemetryEventResponse[];
}

export interface EventEvidenceResponse {
  alert_id?: string | null;
  evidence_events: TelemetryEventResponse[];
  uncertainty_notes: string[];
  total_events: number;
}
