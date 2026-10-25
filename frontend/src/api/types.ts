export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export interface Coverage {
  total_packages: number;
  evaluated: number;
  cached: number;
  not_evaluated: number;
  unsupported: number;
  error: number;
  unresolved: number;
  graph_complete: boolean;
  percent_evaluated: number;
  notes: string[];
}

export interface ScanSummary {
  severity: Record<Severity, number>;
  findings: number;
  packages: number;
  coverage: Coverage;
  advisory_source: { mode: string; provider: string; snapshot_id?: string | null; snapshot_generated?: string | null; fetched_at?: string | null; offline: boolean; notes: string[] };
  checksum: string;
  graph_complete: boolean;
  warnings: number;
  formats: string[];
}

export interface ScanMeta {
  id: string;
  project_id: string;
  state: "queued" | "parsing" | "enriching" | "analyzing" | "completed" | "partial" | "failed" | "cancelled";
  label: string | null;
  enrichment: string;
  inputs: { name: string; size: number; sha256: string }[];
  demo: boolean;
  error: string | null;
  summary: ScanSummary | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  project?: string;
}

export interface Project {
  id: string;
  name: string;
  description: string | null;
  demo: boolean;
  created_at: string;
  scan_count: number;
  latest_scan: ScanMeta | null;
  active_scan: ScanMeta | null;
}

export interface Overview {
  projects: number;
  demo_projects: number;
  scans: number;
  latest_scans: ScanMeta[];
  totals: Record<string, number>;
  severity: Record<Severity, number>;
  trend: {
    scan_id: string;
    project_id: string;
    project: string;
    label: string | null;
    created_at: string;
    severity: Record<Severity, number>;
    percent_evaluated: number | null;
    snapshot: string | null;
    mode: string | null;
    demo: boolean;
  }[];
  has_demo_data: boolean;
}

export interface PathSummary {
  paths: { nodes: string[]; edge_types: string[]; inferred: boolean }[];
  total_found: number;
  truncated: boolean;
  introducers: string[];
  reachable_from_root: boolean;
  warning: string | null;
}

export interface ScoreFactor {
  name: string;
  weight: number;
  value: number | null;
  evidence: string;
}

export interface Finding {
  id: string;
  fingerprint: string;
  component_id: string;
  ecosystem: string;
  package: string;
  version: string;
  purl: string | null;
  advisory: {
    id: string;
    aliases: string[];
    merged_ids: string[];
    summary: string | null;
    details: string | null;
    published: string | null;
    modified: string | null;
    severity: { level: Severity; score: number | null; vector: string | null; vector_type: string | null; source: string | null; note: string | null };
    references: { type: string | null; url: string }[];
    fixed_versions: string[];
    source: string;
    raw_hash: string | null;
  };
  match: { basis: string; rationale: string; local_verification: string };
  paths: PathSummary;
  direct: boolean;
  scopes: string[];
  priority: { score: number | null; confidence: number; factors: ScoreFactor[]; note: string };
  source: string;
  fetched_at: string | null;
  snapshot_id: string | null;
  location: { file: string; line: number | null; detail: string | null } | null;
  triage: { status: string; rationale?: string; expires?: string | null; author?: string | null; expired: boolean };
  path_labels?: string[][];
  names?: Record<string, string>;
  fix?: { candidate_versions: string[]; introducers: string[]; note: string; direct: boolean } | null;
  triage_history?: { from: string | null; to: string; rationale: string; expires: string | null; author: string | null; at: string }[];
  scan?: { id: string; created_at: string; demo: boolean; advisory_source: ScanSummary["advisory_source"] };
}

export interface ComponentRow {
  id: string;
  name: string;
  version: string | null;
  ecosystem: string;
  purl: string | null;
  declared: string | null;
  resolved: boolean;
  direct: boolean;
  scopes: string[];
  licenses: string[];
  source: string | null;
  state: string;
  state_note: string | null;
  advisories: number;
  max_severity: Severity | null;
  depth: number | null;
  parents: number;
}

export interface GraphData {
  mode: string;
  truncated: boolean;
  note: string | null;
  total_nodes: number;
  analysis: Record<string, number | boolean>;
  nodes: {
    id: string;
    label: string;
    version: string | null;
    ecosystem: string;
    kind: string;
    depth: number | null;
    scopes: string[];
    direct: boolean;
    source: string | null;
    state: string | null;
    severity: Severity | null;
    findings: number;
  }[];
  edges: {
    id: string;
    source: string;
    target: string;
    type: string;
    constraint: string | null;
    confidence: string;
    provenance: { file: string; line: number | null; detail: string | null } | null;
  }[];
}

export interface Scenario {
  id: string;
  name: string;
  mode: "candidate_lockfile" | "hypothetical";
  status: "confirmed_by_candidate_scan" | "predicted_partial" | "unknown" | "blocked";
  full_reresolution: boolean;
  created_at: string;
  base_scan_id: string;
  assumptions: string[];
  advisories_removed: FindingRef[];
  advisories_remaining: FindingRef[];
  newly_introduced: FindingRef[];
  unknown: FindingRef[];
  dependencies_changed: { ecosystem: string; name: string; change: string; before: string | null; after: string | null }[];
  unresolved_constraints: string[];
  coverage_delta: Record<string, number>;
  evidence: {
    component: string;
    current_version: string | null;
    candidate_version: string | null;
    obtained_from: string;
    advisories_before: string[];
    advisories_after: string[];
    parents_impacted: string[];
    full_reresolution: boolean;
    status: string;
    candidate_evaluated: boolean;
    source_freshness: string | null;
  }[];
  explanation: string;
  blocked_reason: string | null;
  operations: { op: string; component: string; version: string | null }[];
}

export interface FindingRef {
  advisory_id: string;
  package: string;
  version: string | null;
  severity: string | null;
  cause: string | null;
}

export interface Comparison {
  left: { scan_id: string; label: string | null; created_at: string; snapshot_id: string | null; advisory_mode: string; percent_evaluated: number; demo: boolean };
  right: { scan_id: string; label: string | null; created_at: string; snapshot_id: string | null; advisory_mode: string; percent_evaluated: number; demo: boolean };
  packages: { ecosystem: string; name: string; change: string; before: string | null; after: string | null }[];
  findings: {
    classification: string;
    cause: string;
    explanation: string;
    ecosystem: string;
    package: string;
    version_before: string | null;
    version_after: string | null;
    advisory_id: string;
    severity_before: string | null;
    severity_after: string | null;
  }[];
  counts: Record<string, number>;
  package_counts: Record<string, number>;
  coverage_delta: Record<string, number>;
  advisory_source_changed: boolean;
  notes: string[];
}

export interface PolicyResult {
  policy: string;
  outcome: "pass" | "warn" | "fail" | "inconclusive";
  exit_code: number;
  baseline_used: boolean;
  violations: { rule_id: string; action: string; message: string }[];
  warnings: { rule_id: string; action: string; message: string }[];
  suppressed: { advisory_id: string; package: string; status: string; expires: string | null; rationale: string }[];
  expired_exceptions: { advisory_id: string; package: string; expires: string | null }[];
  unknown_data: Record<string, number>;
  notes: string[];
}
