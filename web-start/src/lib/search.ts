// Search parameters are validated with a Standard Schema (https://standardschema.dev) on every route that has them:
// a field that does not match its pattern and bound is dropped, so a malformed parameter falls back to the default
// and never reaches the API. The validator is chosen by the U09 bundle measurement (docs/web-ui.md, "Stack choice").
export type FieldRule = readonly [pattern: RegExp, maxLength: number];

export interface SearchSchema<T> {
  readonly "~standard": {
    readonly version: 1;
    readonly vendor: "sentinel";
    readonly validate: (input: unknown) => { value: T };
    readonly types?: { readonly input: Record<string, unknown>; readonly output: T };
  };
}

export function searchSchema<const R extends Record<string, FieldRule>>(rules: R): SearchSchema<{ [K in keyof R]?: string }> {
  return {
    "~standard": {
      version: 1,
      vendor: "sentinel",
      validate(input: unknown) {
        const out: Record<string, string> = {};
        const source = (input && typeof input === "object" ? input : {}) as Record<string, unknown>;
        for (const [key, [pattern, max]] of Object.entries(rules)) {
          let v = source[key];
          if (typeof v === "number" && Number.isSafeInteger(v)) v = String(v);
          if (typeof v === "string" && v.length > 0 && v.length <= max && pattern.test(v)) out[key] = v;
        }
        return { value: out as { [K in keyof R]?: string } };
      },
    },
  };
}

export const NO_CONTROL = /^[^\u0000-\u001f\u007f]+$/;
export const DIGITS = /^[1-9][0-9]{0,9}$/;
export const HEX_PREFIX = /^[0-9a-f]{7,40}$/;
export const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
export const CURSOR = /^[A-Za-z0-9_=:.-]+$/;
