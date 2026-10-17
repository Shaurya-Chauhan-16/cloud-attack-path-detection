/**
 * Attack graph types matching backend src.api.schemas.graph and src.shared.models
 */

export interface GraphNode {
  node_id: string;
  node_type: string;
  ip_addresses: string[];
  label?: string | null;
  properties: Record<string, any>;
}

export interface GraphEdge {
  edge_id: string;
  source_node: string;
  target_node: string;
  relation: string;
  observed_or_inferred: "observed" | "permitted" | "inferred" | string;
  evidence_event_ids: string[];
  valid_time?: string | null;
  confidence_reason?: string | null;
  protocol?: string | null;
  port?: number | null;
  details: Record<string, any>;
}

export interface CandidatePath {
  path_id: string;
  node_ids: string[];
  edge_ids: string[];
  evidence_event_ids: string[];
  relationship_types: string[];
  start_time?: string | null;
  end_time?: string | null;
  contains_inferred_relationships: boolean;
  uncertainty_reasons: string[];
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  candidate_paths: CandidatePath[];
  total_nodes: number;
  total_edges: number;
  inferred_edge_count: number;
  observed_edge_count: number;
  permitted_edge_count: number;
}
