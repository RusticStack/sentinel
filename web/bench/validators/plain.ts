// A hand-written Standard Schema: each field kept when it matches, dropped otherwise.
const FIELDS: Record<string, [RegExp, number]> = {
  ref: [/^[^\u0000-\u001f\u007f]+$/, 256], pr: [/^[1-9][0-9]{0,9}$/, 10], sha: [/^[0-9a-f]{7,40}$/, 40], before: [/^[A-Za-z0-9_-]+$/, 256],
};
export const RunFilters = {
  "~standard": {
    version: 1, vendor: "sentinel",
    validate(input: unknown) {
      const out: Record<string, string> = {};
      const issues: { message: string; path: string[] }[] = [];
      for (const [k, [re, max]] of Object.entries(FIELDS)) {
        const v = (input as Record<string, unknown>)?.[k];
        if (v === undefined) continue;
        if (typeof v === "string" && v.length <= max && re.test(v)) out[k] = v; else issues.push({ message: "invalid", path: [k] });
      }
      return issues.length ? { issues } : { value: out };
    },
  },
};
