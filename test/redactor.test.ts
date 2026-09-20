import { describe, expect, it } from "vitest";
import {
  getBuiltinRules,
  literalRule,
  patternRule,
  REDACTION,
  redactText,
} from "../src/redactor.js";

describe("redactText", () => {
  it("redacts conservative built-in secret formats", () => {
    const secrets = [
      ["sk-ant-api03", "abcdefghijklmnopqrstuvwxyz123456"].join("-"),
      ["sk-proj", "abcdefghijklmnopqrstuvwxyz123456"].join("-"),
      ["ghp", "abcdefghijklmnopqrstuvwxyz123456"].join("_"),
      ["xoxb", "1234567890", "abcdefghijklmnopqrst"].join("-"),
      ["AIza", "abcdefghijklmnopqrstuvwxyz1234567890"].join(""),
      ["eyJabcdefghijk", "abcdefghijkl", "abcdefghijkl"].join("."),
      [
        "-----BEGIN",
        " PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----",
      ].join(""),
    ];

    for (const secret of secrets) {
      const result = redactText(`before ${secret} after`, getBuiltinRules());
      expect(result.value).toBe(`before ${REDACTION} after`);
      expect(result.count).toBe(1);
    }
  });

  it("redacts configured literals without interpreting regex characters", () => {
    const result = redactText("send a.b+c and keep aXbbc", [
      literalRule("literal", "a.b+c"),
    ]);
    expect(result.value).toBe("send ***** and keep aXbbc");
  });

  it("merges overlapping matches and reports their categories", () => {
    const result = redactText("xxabcdefghyy", [
      patternRule("outer", "abcdefgh"),
      patternRule("inner", "cdef"),
    ]);
    expect(result.value).toBe("xx*****yy");
    expect(result.count).toBe(1);
    expect(result.categories).toEqual({ outer: 1, inner: 1 });
  });

  it("keeps adjacent matches distinct", () => {
    const result = redactText("secretsecret", [
      literalRule("literal", "secret"),
    ]);
    expect(result.value).toBe("**********");
    expect(result.count).toBe(2);
  });

  it("returns the original string when there are no matches", () => {
    const result = redactText("ordinary source code", getBuiltinRules());
    expect(result).toEqual({
      value: "ordinary source code",
      count: 0,
      categories: {},
    });
  });
});

describe("patternRule", () => {
  it.each(["(a+)+", "(a*){2}", "(a{1,3})+", "(a+)\\1", "(?<=secret)value"])(
    "rejects unsafe pattern %s",
    (pattern) => {
      expect(() => patternRule("unsafe", pattern)).toThrow();
    },
  );

  it("rejects empty matches", () => {
    expect(() => patternRule("empty", "a*")).toThrow(/empty string/);
  });
});
