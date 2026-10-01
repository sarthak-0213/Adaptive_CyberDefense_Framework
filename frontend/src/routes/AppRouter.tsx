import { Navigate, Route, Routes } from "react-router-dom";

import DashboardLayout from "../layouts/DashboardLayout";

import Dashboard from "../pages/Dashboard";
import Login from "../pages/Login";
import Alerts from "../pages/Alerts";
import Security from "../pages/Security";
import ThreatAnalytics from "../pages/ThreatAnalytics";
import Reports from "../pages/Reports";
import Settings from "../pages/Settings";
import SecurityAssessment from "../pages/SecurityAssessment";

import ProtectedRoute from "./ProtectedRoute";


export default function AppRouter() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      <Route
        element={
          <ProtectedRoute>
            <DashboardLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="security" element={<Security />} />
        <Route path="threats" element={<ThreatAnalytics />} />
        <Route path="reports" element={<Reports />} />
        <Route path="security-assessment" element={<SecurityAssessment />} />
        <Route path="settings" element={<Settings />} />
      </Route>


      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
