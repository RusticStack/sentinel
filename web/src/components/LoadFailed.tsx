import { useRouter } from "@tanstack/react-router";
import { Alert, Button } from "./ui.tsx";

/** Shown in place of a section whose read failed, so an outage is never drawn as an empty list. */
export function LoadFailed({ what, words }: { what: string; words: string }) {
  const router = useRouter();
  return (
    <Alert color="error" icon="circle-alert" role="alert" title={`Could not load ${what}.`} description={words}>
      <div className="pt-1"><Button size="sm" color="neutral" variant="outline" label="Try again" onClick={() => { void router.invalidate(); }} /></div>
    </Alert>
  );
}
