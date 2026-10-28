import * as v from "valibot";
const text = (re: RegExp, max: number) => v.optional(v.pipe(v.string(), v.maxLength(max), v.regex(re)));
export const RunFilters = v.object({
  ref: text(/^[^\u0000-\u001f\u007f]+$/, 256),
  pr: text(/^[1-9][0-9]{0,9}$/, 10),
  sha: text(/^[0-9a-f]{7,40}$/, 40),
  before: text(/^[A-Za-z0-9_-]+$/, 256),
});
