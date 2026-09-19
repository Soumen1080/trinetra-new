import { describe, expect, it } from "vitest";
import { riskBand, riskCopy, titleCase } from "./risk";

describe("risk language", () => {
  it("never turns a missing priority into a low-risk band", () => {
    expect(riskBand(undefined)).toBe("none");
    expect(riskCopy[riskBand(undefined)].label).toBe("Not assessed");
  });

  it("preserves a concrete action for every known band", () => {
    expect(riskCopy.p0.action).toBe("Act now");
    expect(riskCopy.p1.action).toBe("Plan next");
    expect(titleCase("cloud_hsm")).toBe("Cloud Hsm");
  });
});
