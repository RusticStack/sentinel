import { useEffect, useRef, useState } from "preact/hooks";

const QUIET_MS = 1600;

/** Flash + “Updated” after a successful panel retry (no Live badge). */
export function useRetryFeedback(): {
  flashClass: string;
  liveMessage: string;
  markUpdated: () => void;
} {
  const [liveMessage, setLiveMessage] = useState("");
  const [flash, setFlash] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const markUpdated = () => {
    setFlash(true);
    setLiveMessage("Updated");
    if (timer.current != null) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      setFlash(false);
      setLiveMessage("");
      timer.current = null;
    }, QUIET_MS);
  };

  useEffect(() => {
    return () => {
      if (timer.current != null) clearTimeout(timer.current);
    };
  }, []);

  return {
    flashClass: flash ? "quiet-refresh-flash" : "",
    liveMessage,
    markUpdated,
  };
}

export function QuietLiveRegion(props: { message: string }) {
  return (
    <span class="sr-only" aria-live="polite" aria-atomic="true">
      {props.message}
    </span>
  );
}
