import fs from "node:fs";
import path from "node:path";
import { JSDOM } from "jsdom";
import { describe, expect, it, vi } from "vitest";

const root = process.cwd();
const read = (name) =>
  fs.readFileSync(path.join(root, "custom_components/openid", name), "utf8");

describe("authentication frontend", () => {
  it("does not revive OAuth state from persistent browser data", () => {
    const source = read("authorize.js");
    expect(source).not.toContain("localStorage");
    expect(source).not.toContain("document.referrer");
    expect(source).not.toContain("innerHTML");
  });

  it("accepts Request objects passed to fetch", async () => {
    const dom = new JSDOM("<body></body>", {
      runScripts: "outside-only",
      url: "https://ha.example/auth/authorize",
    });
    const originalFetch = vi.fn(async () => new Response("{}", { status: 200 }));
    dom.window.fetch = originalFetch;
    dom.window.Request = Request;
    dom.window.Response = Response;
    dom.window.eval(read("authorize.js"));

    const request = new Request("https://ha.example/api/test");
    await dom.window.fetch(request);
    expect(originalFetch).toHaveBeenCalledWith(request);
  });

  it("stores error messages only in session storage", () => {
    const dom = new JSDOM(
      '<body data-alert-type="error" data-alert-message="failed"></body>',
      { runScripts: "outside-only", url: "https://ha.example/" },
    );
    dom.window.eval(read("error.js"));
    expect(dom.window.sessionStorage.getItem("openidAlertType")).toBe("error");
    expect(dom.window.sessionStorage.getItem("openidAlertMessage")).toBe("failed");
  });

  it("uses external scripts in authentication templates", () => {
    for (const template of ["android_waiting_template.html", "error_template.html"]) {
      const dom = new JSDOM(read(template));
      const inlineScripts = [...dom.window.document.querySelectorAll("script")].filter(
        (script) => !script.src,
      );
      expect(inlineScripts).toHaveLength(0);
    }
  });
});
