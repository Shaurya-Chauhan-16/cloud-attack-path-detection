import { fetchApi } from "./client";
import { CaseCreateRequest, CaseResponse } from "../types/case";

export async function getCases(): Promise<CaseResponse[]> {
  return fetchApi<CaseResponse[]>("/cases");
}

export async function getCaseById(caseId: string): Promise<CaseResponse> {
  return fetchApi<CaseResponse>(`/cases/${encodeURIComponent(caseId)}`);
}

export async function createCase(data: CaseCreateRequest): Promise<CaseResponse> {
  return fetchApi<CaseResponse>("/cases", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function addAlertToCase(caseId: string, alertId: string): Promise<CaseResponse> {
  return fetchApi<CaseResponse>(`/cases/${encodeURIComponent(caseId)}/alerts/${encodeURIComponent(alertId)}`, {
    method: "POST",
  });
}
