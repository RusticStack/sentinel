import { useState } from "react";

/** State seeded from loader data that starts over whenever the loader produces new data (another tenant, a re-load). */
export function useLoaded<T>(loaded: T): [T, (next: T) => void] {
  const [state, setState] = useState<{ from: T; value: T }>({ from: loaded, value: loaded });
  if (state.from !== loaded) {
    const fresh = { from: loaded, value: loaded };
    setState(fresh);
    return [loaded, (value: T) => setState({ from: loaded, value })];
  }
  return [state.value, (value: T) => setState({ from: loaded, value })];
}
