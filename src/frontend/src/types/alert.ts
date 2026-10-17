/**
 * Alert contract types matching backend src.api.schemas.alerts
 */

export type PriorityLevel = "low" | "medium" | "high" | "critical";

export interface PriorityScoreResult {
  final_score: number;
  priority_level: PriorityLevel;
  factor_contributions: Record<string, number>;
  explanation: string;
  uncertainty_reasons: string[];
  scoring_version: string;
  missing_fields: string[];
}

export interface AlertResponse {
  alert_id: string;
  rule_id: string;
  rule_version: string;
  priority: PriorityLevel;
  explanation: string;
  evidence_event_ids: string[];
  related_resource_ids: string[];
  created_at: string;
  case_id?: string | null;
  details: Record<string, any>;
  score_result?: PriorityScoreResult | null;
}

export interface AlertListResponse {
  total: number;
  items: AlertResponse[];
}

export interface AlertFilterParams {
  priority?: PriorityLevel;
  rule_id?: string;
  resource_id?: string;
  case_id?: string;
  limit?: number;
  offset?: number;
}
