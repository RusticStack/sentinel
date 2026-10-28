import * as z from "zod/mini";
const text = (re: RegExp, max: number) => z.optional(z.string().check(z.maxLength(max), z.regex(re)));
export const RunFilters = z.object({
  ref: text(/^[^\u0000-\u001f\u007f]+$/, 256),
  pr: text(/^[1-9][0-9]{0,9}$/, 10),
  sha: text(/^[0-9a-f]{7,40}$/, 40),
  before: text(/^[A-Za-z0-9_-]+$/, 256),
});
