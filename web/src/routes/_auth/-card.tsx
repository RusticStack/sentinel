// The signed-out pages' card: a header with the view's one level-one heading, the body and an optional footer.
// (The leading dash keeps the route generator from treating this file as a route.)
import { forwardRef, type ReactNode } from "react";
import { cx, Icon } from "../../components/ui.tsx";

export function AuthCard({ header, footer, children, className, bodyClassName }: { header: ReactNode; footer?: ReactNode; children: ReactNode; className?: string; bodyClassName?: string }) {
  return (
    <div className={cx("w-full min-w-0 rounded-lg border border-line bg-canvas shadow-sm", className)}>
      <div className="border-b border-line px-4 py-4 sm:px-6">{header}</div>
      <div className={cx("px-4 py-5 sm:px-6", bodyClassName)}>{children}</div>
      {footer ? <div className="border-t border-line px-4 py-4 sm:px-6">{footer}</div> : null}
    </div>
  );
}

/** The icon and the heading; a heading that the view moves focus to takes a ref and is focusable from script only. */
export const AuthTitle = forwardRef<HTMLHeadingElement, { icon?: string; children: ReactNode; focusable?: boolean }>(function AuthTitle({ icon = "radar", children, focusable }, ref) {
  return (
    <div className="flex items-center gap-2">
      <Icon name={icon} className="size-6 text-primary" />
      <h1 ref={ref} tabIndex={focusable ? -1 : undefined} className="text-lg font-semibold text-strong focus:outline-none">{children}</h1>
    </div>
  );
});
