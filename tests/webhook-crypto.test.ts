import { describe, it, expect } from "vitest";
import { signWebhookPayload, verifyWebhookSignature } from "../src/lib/webhook-crypto";

describe("webhook-crypto", () => {
  it("signs deterministically", () => {
    const sig = signWebhookPayload("secret", '{"a":1}');
    expect(sig).toHaveLength(64);
    expect(signWebhookPayload("secret", '{"a":1}')).toBe(sig);
  });

  it("verifies valid signatures", () => {
    const body = JSON.stringify({ type: "PAYMENT_SUCCESS" });
    const sig = signWebhookPayload("whsec_test", body);
    expect(verifyWebhookSignature("whsec_test", body, sig)).toBe(true);
  });

  it("rejects tampered signatures", () => {
    const body = "{}";
    const sig = signWebhookPayload("whsec_test", body);
    expect(verifyWebhookSignature("whsec_test", body, sig + "ff")).toBe(false);
    expect(verifyWebhookSignature("other", body, sig)).toBe(false);
  });

  it("rejects signatures with mismatched length", () => {
    const body = "{}";
    expect(verifyWebhookSignature("sec", body, "ab")).toBe(false);
  });

  it("rejects empty signature", () => {
    const body = "{}";
    const sig = signWebhookPayload("sec", body);
    expect(verifyWebhookSignature("sec", body, "")).toBe(false);
    expect(sig).not.toBe("");
  });

  // --- Edge cases per issue #2 ---

  it("rejects a wrong-length signature (31 chars instead of 64)", () => {
    const body = '{"event":"payment.created"}';
    const wrongLengthSig = "a".repeat(31);
    expect(verifyWebhookSignature("whsec_test", body, wrongLengthSig)).toBe(false);
  });

  it("rejects a wrong-length signature (65 chars instead of 64)", () => {
    const body = '{"event":"payment.created"}';
    const wrongLengthSig = "a".repeat(65);
    expect(verifyWebhookSignature("whsec_test", body, wrongLengthSig)).toBe(false);
  });

  it("rejects a truncated body (missing closing brace)", () => {
    const fullBody = '{"event":"payment.created","amount":100}';
    const truncatedBody = '{"event":"payment.created","amount":100';
    const sig = signWebhookPayload("whsec_test", fullBody);
    expect(verifyWebhookSignature("whsec_test", truncatedBody, sig)).toBe(false);
  });

  it("rejects a tampered body (one byte changed)", () => {
    const originalBody = '{"event":"payment.created","amount":100}';
    const tamperedBody = '{"event":"payment.created","amount":101}';
    const sig = signWebhookPayload("whsec_test", originalBody);
    expect(verifyWebhookSignature("whsec_test", tamperedBody, sig)).toBe(false);
  });

  it("rejects a valid signature for a different secret", () => {
    const body = '{"event":"payment.created"}';
    const sig = signWebhookPayload("whsec_correct", body);
    expect(verifyWebhookSignature("whsec_wrong", body, sig)).toBe(false);
  });

  it("rejects a signature with non-hex characters", () => {
    const body = '{"event":"payment.created"}';
    // 64 chars but contains 'g' and 'z' which are not valid hex
    const nonHexSig = "g".repeat(32) + "z".repeat(32);
    expect(verifyWebhookSignature("whsec_test", body, nonHexSig)).toBe(false);
  });

  it("accepts a valid signature with an empty body", () => {
    const body = "";
    const sig = signWebhookPayload("whsec_test", body);
    expect(sig).toHaveLength(64);
    expect(verifyWebhookSignature("whsec_test", body, sig)).toBe(true);
  });

  it("rejects an uppercase version of a valid signature", () => {
    const body = '{"event":"payment.created"}';
    const sig = signWebhookPayload("whsec_test", body);
    // HMAC-SHA256 hex output is lowercase; uppercase should not match
    expect(verifyWebhookSignature("whsec_test", body, sig.toUpperCase())).toBe(false);
  });

  it("rejects a signature with leading/trailing whitespace", () => {
    const body = '{"event":"payment.created"}';
    const sig = signWebhookPayload("whsec_test", body);
    expect(verifyWebhookSignature("whsec_test", body, ` ${sig} `)).toBe(false);
  });

  it("produces different signatures for different bodies with same secret", () => {
    const sig1 = signWebhookPayload("whsec_test", '{"a":1}');
    const sig2 = signWebhookPayload("whsec_test", '{"a":2}');
    expect(sig1).not.toBe(sig2);
    expect(verifyWebhookSignature("whsec_test", '{"a":1}', sig2)).toBe(false);
    expect(verifyWebhookSignature("whsec_test", '{"a":2}', sig1)).toBe(false);
  });
});
