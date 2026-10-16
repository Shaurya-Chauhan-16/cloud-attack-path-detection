import { fetchApi } from "./client";
import { AlertFilterParams, AlertListResponse, AlertResponse } from "../types/alert";

export async function getAlerts(params?: AlertFilterParams): Promise<AlertListResponse> {
  const query = new URLSearchParams();
  if (params?.priority) query.append("priority", params.priority);
  if (params?.rule_id) query.append("rule_id", params.rule_id);
  if (params?.resource_id) query.append("resource_id", params.resource_id);
  if (params?.case_id) query.append("case_id", params.case_id);
  if (params?.limit) query.append("limit", params.limit.toString());
  if (params?.offset) query.append("offset", params.offset.toString());

  const qs = query.toString();
  return fetchApi<AlertListResponse>(`/alerts${qs ? `?${qs}` : ""}`);
}

export async function getAlertById(alertId: string): Promise<AlertResponse> {
  return fetchApi<AlertResponse>(`/alerts/${encodeURIComponent(alertId)}`);
}
