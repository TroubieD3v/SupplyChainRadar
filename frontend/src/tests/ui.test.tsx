import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Dial, Empty, SeverityChip, StateChip } from "../components/ui";

describe("honest UI states", () => {
  it("labels unknown severity explicitly instead of hiding it", () => {
    render(<SeverityChip level="unknown" />);
    expect(screen.getByText("unknown")).toHaveAttribute("title", expect.stringContaining("no severity"));
  });
  it("shows not-evaluated as a warning state, never as clean", () => {
    render(<StateChip state="not_evaluated" />);
    expect(screen.getByText("not evaluated")).toBeInTheDocument();
  });
  it("describes the dial for assistive tech", () => {
    render(<Dial outer={50} inner={25} center={3} caption="Confirmed advisories" />);
    expect(screen.getByRole("img")).toHaveAccessibleName(/50 percent evaluated/);
  });
  it("renders an empty state with its explanation", () => {
    render(<Empty title="Nothing imported yet">Create a project.</Empty>);
    expect(screen.getByRole("heading", { name: "Nothing imported yet" })).toBeInTheDocument();
  });
});
