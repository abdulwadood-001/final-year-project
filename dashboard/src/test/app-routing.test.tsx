import { QueryClient } from "@tanstack/react-query";
import { createRouter, rootRouteId } from "@tanstack/react-router";
import { describe, expect, it } from "vitest";

import { routeTree } from "@/routeTree.gen";

// Match routes without rendering (no API in the unit-test run).
const router = createRouter({ routeTree, context: { queryClient: new QueryClient() } });
const leaf = (path: string) => router.matchRoutes(path).at(-1)?.routeId;

describe("App routing", () => {
  it.each([
    ["/", "/"],
    ["/attackers", "/attackers/"],
    ["/attackers/203.0.113.7", "/attackers/$ip"],
    ["/detections", "/detections"],
    ["/devices", "/devices/"],
    ["/devices/smartlock", "/devices/$device"],
    ["/sessions", "/sessions/"],
    ["/sessions/1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed", "/sessions/$sessionId"],
    ["/malware", "/malware"],
    ["/iocs", "/iocs"],
    ["/reports", "/reports"],
    ["/search", "/search"],
  ])("%s renders %s", (path, id) => {
    expect(leaf(path)).toBe(id);
  });

  it("detail pages are not swallowed by their list page (v0.6 UI had no <Outlet/>)", () => {
    expect(leaf("/attackers/1.2.3.4")).not.toBe("/attackers/");
  });

  it("unknown paths fall back to not-found, not to a page", () => {
    expect(leaf("/definitely/not/here")).toBe(rootRouteId);
  });
});
