import { FolderUp, ScanLine } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { useSelection } from "../app/state";
import type { ScanMeta } from "../api/types";
import { Button, Empty, ErrorBox, Spinner, StateChip } from "./ui";

/** Renders children only when a finished scan is selected; otherwise an honest empty/pending/failed state. */
export function RequireScan({ children }: { children: (scan: ScanMeta) => ReactNode }) {
  const { loading, error, projects, project, scan, reload } = useSelection();
  if (loading) return <Spinner label="Loading projects" />;
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (projects.length === 0)
    return (
      <Empty icon={<FolderUp className="h-6 w-6" />} title="Nothing imported yet" actions={<Link to="/projects"><Button>Create a project</Button></Link>}>
        Create a project and import a lockfile or SBOM to see packages, dependency paths and advisories here.
      </Empty>
    );
  if (!scan)
    return (
      <Empty icon={<ScanLine className="h-6 w-6" />} title={`No scans in “${project?.name}”`} actions={<Link to="/projects"><Button>Import a file</Button></Link>}>
        Import a lockfile or SBOM to create the first scan snapshot for this project.
      </Empty>
    );
  if (["queued", "parsing", "enriching", "analyzing"].includes(scan.state))
    return (
      <div className="rounded-3xl bg-surface-low p-8">
        <StateChip state={scan.state} />
        <p className="mt-3 text-muted">The scan is running. This page updates automatically.</p>
      </div>
    );
  if (scan.state === "failed" || scan.state === "cancelled")
    return (
      <Empty icon={<ScanLine className="h-6 w-6" />} title={`Scan ${scan.state}`} actions={<Link to="/scan"><Button variant="outline">Inspect scan</Button></Link>}>
        {scan.error ?? "This scan produced no result."}
      </Empty>
    );
  return <>{children(scan)}</>;
}
