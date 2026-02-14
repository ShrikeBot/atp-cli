import { describe, it, expect } from "vitest";
import { validateTimestamp } from "../src/lib/timestamp.js";

describe("Timestamp Validation", () => {
    it("accepts a current timestamp", () => {
        const now = Math.floor(Date.now() / 1000);
        expect(() => validateTimestamp(now)).not.toThrow();
    });

    it("accepts a timestamp within 2 hours", () => {
        const oneHourAgo = Math.floor(Date.now() / 1000) - 3600;
        expect(() => validateTimestamp(oneHourAgo)).not.toThrow();
    });

    it("rejects a timestamp more than 2 hours old", () => {
        const threeHoursAgo = Math.floor(Date.now() / 1000) - 3 * 3600;
        expect(() => validateTimestamp(threeHoursAgo)).toThrow("in the past");
    });

    it("rejects a timestamp more than 2 hours in the future", () => {
        const threeHoursAhead = Math.floor(Date.now() / 1000) + 3 * 3600;
        expect(() => validateTimestamp(threeHoursAhead)).toThrow("in the future");
    });
});
