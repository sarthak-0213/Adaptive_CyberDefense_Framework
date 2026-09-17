import api from "./client";
import type { Alert } from "../types/dashboard";

export interface AlertInput {
  title: string;
  violation_type: string;
  severity?: string;
  description?: string;
}

export const getAlerts = async (): Promise<Alert[]> => {
  const response = await api.get("/api/v1/alerts");
  return response.data;
};

export const createAlert = async (data: AlertInput): Promise<Alert> => {
  const response = await api.post("/api/v1/alerts", data);
  return response.data;
};

export const resolveAlert = async (id: string | number, status: string = "resolved"): Promise<Alert> => {
  const response = await api.put(`/api/v1/alerts/${id}/resolve`, { status });
  return response.data;
};
