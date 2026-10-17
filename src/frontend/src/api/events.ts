import { fetchApi } from "./client";
import { EventEvidenceResponse, EventListResponse, EventSource, TelemetryEventResponse } from "../types/event";

export async function getEvents(source?: EventSource, limit = 50, offset = 0): Promise<EventListResponse> {
  const query = new URLSearchParams();
  if (source) query.append("source", source);
  query.append("limit", limit.toString());
  query.append("offset", offset.toString());

  return fetchApi<EventListResponse>(`/events?${query.toString()}`);
}

export async function getEventById(eventId: string): Promise<TelemetryEventResponse> {
  return fetchApi<TelemetryEventResponse>(`/events/${encodeURIComponent(eventId)}`);
}

export async function getAlertEvidence(alertId: string): Promise<EventEvidenceResponse> {
  return fetchApi<EventEvidenceResponse>(`/events/evidence/alert/${encodeURIComponent(alertId)}`);
}
