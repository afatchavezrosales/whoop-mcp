import { describe, expect, it } from "vitest";
import { clampEndToNow, sanitizeNextToken } from "../../src/mcp-server";

describe("sanitizeNextToken", () => {
	it("ignora la basura que algunos modelos meten en el campo opcional", () => {
		for (const junk of [" ", ": ", ".*", "1", ")}", "The user supplied a detailed background context but", ""]) {
			expect(sanitizeNextToken(junk)).toBeUndefined();
		}
		expect(sanitizeNextToken(undefined)).toBeUndefined();
	});

	it("deja pasar un token real de WHOOP", () => {
		expect(sanitizeNextToken(" MTIzOjEyMzEyMw== ")).toBe("MTIzOjEyMzEyMw==");
		expect(sanitizeNextToken("eyJ0cyI6MTcyNzU2Nzg5MH0")).toBe("eyJ0cyI6MTcyNzU2Nzg5MH0");
	});
});

describe("clampEndToNow", () => {
	const now = new Date("2026-09-29T07:30:00.000Z");
	it("recorta un end futuro a ahora", () => {
		expect(clampEndToNow("2026-09-29T22:00:00.000Z", now)).toBe(now.toISOString());
	});
	it("respeta un end pasado y la ausencia de end", () => {
		expect(clampEndToNow("2026-09-28T22:00:00.000Z", now)).toBe("2026-09-28T22:00:00.000Z");
		expect(clampEndToNow(undefined, now)).toBeUndefined();
	});
});
