/**
 * Case management types matching backend src.api.schemas.cases
 */

import { PriorityLevel } from "./alert";

export interface CaseCreateRequest {
  title: string;
  description?: string;
  alert_ids?: string[];
  priority?: PriorityLevel;
  tags?: string[];
}

export interface CaseResponse {
  case_id: string;
  title: string;
  description?: string | null;
  priority: PriorityLevel;
  status: string;
  alert_ids: string[];
  tags: string[];
  created_at: string;
  updated_at: string;
  persistence_mode: string;
}
