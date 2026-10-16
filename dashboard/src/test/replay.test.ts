import { describe, expect, it } from "vitest";
import { toReplay } from "@/lib/replay";
import { list, protoLabel, isMalicious, fmtBytes } from "@/lib/api";
import type { SessionEvent } from "@/lib/api";

const ev = (event_type: string, extra: Partial<SessionEvent> = {}): SessionEvent => ({
  id: 1,
  ts: "2026-10-15T10:00:00Z",
  event_type,
  username: null,
  password: null,
  success: null,
  command: null,
  payload: null,
  raw: {},
  ...extra,
});

describe("session replay", () => {
  it("renders auth, command output, captures and downloads in order", () => {
    const lines = toReplay(
      [
        ev("connect", { raw: { dst_port: 2222 } }),
        ev("auth", {
          username: "root",
          password: "xc3511",
          success: true,
          raw: { method: "password" },
        }),
        ev("command", {
          command: "uname -a",
          payload: "Linux smartlock 4.14.98",
          mitre: [
            { id: "T1059.004", name: "Unix Shell" },
            { id: "T1082", name: "System Information Discovery" },
          ],
        }),
        ev("download_attempt", { payload: "http://198.51.100.23/bins/arm7" }),
        ev("file_capture", {
          raw: { sha256: "a".repeat(64), mime_type: "application/x-elf", arch: "ARM (32-bit LE)" },
        }),
        ev("disconnect", { raw: { reason: "closed", duration: 4.2 } }),
      ],
      "SSH",
    );
    expect(lines.map((l) => l.type)).toEqual([
      "connect",
      "auth",
      "command",
      "output",
      "download_attempt",
      "file_capture",
      "disconnect",
    ]);
    expect(lines[1]?.detail).toContain("root:xc3511 → accepted");
    expect(lines[1]?.tone).toBe("critical");
    expect(lines[3]?.dir).toBe("out");
    expect(lines[2]?.mitre?.length).toBe(2);
    expect(lines[5]?.detail).toContain("ARM");
  });
});

describe("helpers", () => {
  it("normalise protocol arrays and labels", () => {
    expect(list(["SSH", "HTTP"])).toEqual(["SSH", "HTTP"]);
    expect(list("SSH,Telnet")).toEqual(["SSH", "Telnet"]);
    expect(list(null)).toEqual([]);
    expect(protoLabel("TELNET")).toBe("Telnet");
  });
  it("YARA verdicts and sizes", () => {
    expect(isMalicious("mirai, generic-iot-elf")).toBe(true);
    expect(isMalicious("CLEAN")).toBe(false);
    expect(isMalicious(null)).toBe(false);
    expect(fmtBytes(2048)).toBe("2.0 KB");
  });
});
