// Judged in the page; the password is never sent anywhere. The meter is classes, not style attributes.
import { PASSWORD_MIN_BYTES, passwordAdvice } from "../lib/onboarding.ts";
import { cx } from "./ui.tsx";

const COLORS = ["bg-error", "bg-error", "bg-warning", "bg-success", "bg-success"];

export function PasswordAdvice({ id, password, context = [] }: { id: string; password: string; context?: string[] }) {
  const advice = passwordAdvice(password, context);
  return (
    <div id={id} className="space-y-1">
      <div className="flex gap-1" aria-hidden="true">
        {[1, 2, 3, 4].map((n) => (
          <span key={n} className={cx("h-1 flex-1 rounded-full", password && advice.score >= n ? COLORS[advice.score] : "bg-accented")} />
        ))}
      </div>
      <p className="text-xs text-muted" aria-live="polite">
        {password
          ? <><span className="font-medium text-fg">{advice.label}.</span> {advice.hints[0] ?? "Looks good."}</>
          : <>At least {PASSWORD_MIN_BYTES} characters. A password manager can make and keep one for you.</>}
      </p>
    </div>
  );
}
