import { fetchApi } from "./client";
import { GraphResponse } from "../types/graph";

export async function getGraph(): Promise<GraphResponse> {
  return fetchApi<GraphResponse>("/graph");
}
