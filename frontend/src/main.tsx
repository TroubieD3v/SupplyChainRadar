import { StrictMode, lazy } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import "./index.css";
import { Layout } from "./app/Layout";
import { SelectionProvider, ThemeProvider } from "./app/state";

const CompareTimeline = lazy(() => import("./pages/Compare"));
const Dependencies = lazy(() => import("./pages/Dependencies"));
const Findings = lazy(() => import("./pages/Findings"));
const GraphPage = lazy(() => import("./pages/GraphPage"));
const Overview = lazy(() => import("./pages/Overview"));
const Policies = lazy(() => import("./pages/Policies"));
const Projects = lazy(() => import("./pages/Projects"));
const Remediation = lazy(() => import("./pages/Remediation"));
const Reports = lazy(() => import("./pages/Reports"));
const ScanDetails = lazy(() => import("./pages/ScanDetails"));

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <BrowserRouter>
        <SelectionProvider>
          <Routes>
            <Route element={<Layout />}>
              <Route index element={<Overview />} />
              <Route path="projects" element={<Projects />} />
              <Route path="scan" element={<ScanDetails />} />
              <Route path="dependencies" element={<Dependencies />} />
              <Route path="graph" element={<GraphPage />} />
              <Route path="findings" element={<Findings />} />
              <Route path="remediation" element={<Remediation />} />
              <Route path="compare" element={<CompareTimeline />} />
              <Route path="policies" element={<Policies />} />
              <Route path="reports" element={<Reports />} />
              <Route path="*" element={<Overview />} />
            </Route>
          </Routes>
        </SelectionProvider>
      </BrowserRouter>
    </ThemeProvider>
  </StrictMode>,
);
