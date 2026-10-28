// The interface's building blocks: native elements styled with Tailwind where the platform is enough, React Aria
// Components where a pattern needs managed focus and keyboard behaviour (select, menu, modal dialog).
import { forwardRef, useEffect, useRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type TextareaHTMLAttributes } from "react";
import { Link } from "@tanstack/react-router";
import {
  Button as AriaButton, Dialog, Header, Heading, Label, ListBox, ListBoxItem, ListBoxSection, Menu, MenuItem, MenuSection, MenuTrigger,
  Modal, ModalOverlay, Popover, Select as AriaSelect, SelectValue, Separator,
} from "react-aria-components";
import { ICONS } from "./icons.ts";

export type Color = "primary" | "neutral" | "success" | "info" | "warning" | "error";

export function cx(...parts: (string | false | null | undefined)[]) { return parts.filter(Boolean).join(" "); }

export function Icon({ name, className = "size-4" }: { name: string; className?: string }) {
  const body = ICONS[name.replace(/^i-lucide-/, "")];
  if (!body) return null;
  return <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" className={cx("shrink-0", className)} dangerouslySetInnerHTML={{ __html: body }} />;
}

const TEXT: Record<Color, string> = {
  primary: "text-primary", neutral: "text-muted", success: "text-success", info: "text-info", warning: "text-warning", error: "text-error",
};
const SOLID: Record<Color, string> = {
  primary: "bg-primary text-on-primary hover:opacity-90", neutral: "bg-strong text-canvas hover:opacity-90", success: "bg-success text-canvas",
  info: "bg-info text-canvas", warning: "bg-warning text-canvas", error: "bg-error text-canvas hover:opacity-90",
};
const SOFT: Record<Color, string> = {
  primary: "bg-primary/10 text-primary hover:bg-primary/15", neutral: "bg-elevated text-fg hover:bg-accented", success: "bg-success/10 text-success",
  info: "bg-info/10 text-info", warning: "bg-warning/10 text-warning", error: "bg-error/10 text-error hover:bg-error/15",
};

export type ButtonVariant = "solid" | "outline" | "soft" | "ghost" | "link";
interface ButtonLook { color?: Color; variant?: ButtonVariant; size?: "xs" | "sm" | "md"; block?: boolean; square?: boolean }
export function buttonClass({ color = "primary", variant = "solid", size = "md", block, square }: ButtonLook, extra?: string) {
  return cx(
    "inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors disabled:opacity-60 disabled:cursor-not-allowed cursor-pointer",
    size === "xs" ? "text-xs px-2 py-1" : size === "sm" ? "text-sm px-2.5 py-1.5" : "text-sm px-3 py-2",
    square && "px-1.5",
    block && "w-full",
    variant === "solid" && SOLID[color],
    variant === "soft" && SOFT[color],
    variant === "outline" && cx("border border-line-strong bg-canvas hover:bg-elevated", color === "neutral" ? "text-fg" : TEXT[color]),
    variant === "ghost" && cx("hover:bg-elevated", color === "neutral" ? "text-fg" : TEXT[color]),
    variant === "link" && cx("px-0 py-0 underline underline-offset-2", TEXT[color]),
    extra,
  );
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & ButtonLook & { icon?: string; trailingIcon?: string; loading?: boolean; label?: ReactNode };
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { color, variant, size, block, square, icon, trailingIcon, loading, label, children, className, type = "button", disabled, ...rest }, ref,
) {
  return (
    <button ref={ref} type={type} disabled={disabled || loading} aria-busy={loading || undefined}
      className={buttonClass({ color, variant, size, block, square }, className)} {...rest}>
      {loading ? <Icon name="loader-circle" className="size-4 animate-spin" /> : icon ? <Icon name={icon} /> : null}
      {label ?? children}
      {trailingIcon ? <Icon name={trailingIcon} /> : null}
    </button>
  );
});

// Links take a plain path: the views build them from identifiers, so typed route templates add nothing here.
export interface PathLinkProps { to: string; search?: Record<string, unknown>; hash?: string; replace?: boolean; className?: string; children?: ReactNode; onClick?: () => void; "aria-label"?: string; "aria-current"?: "page"; title?: string; id?: string }
export function PathLink({ to, ...rest }: PathLinkProps) {
  return <Link to={to as "/"} {...(rest as object)} />;
}

export function ButtonLink({ color, variant, size, block, icon, label, children, className, ...rest }: PathLinkProps & ButtonLook & { icon?: string; label?: ReactNode }) {
  return (
    <PathLink className={buttonClass({ color, variant, size, block }, className)} {...rest}>
      {icon ? <Icon name={icon} /> : null}
      {label ?? children}
    </PathLink>
  );
}

export function TextLink({ className, ...rest }: PathLinkProps) {
  return <PathLink className={cx("text-primary underline-offset-2 hover:underline", className)} {...rest} />;
}

export function Alert({ color = "info", title, description, icon, children, className, role }: { color?: Color; title?: ReactNode; description?: ReactNode; icon?: string; children?: ReactNode; className?: string; role?: "alert" | "status" }) {
  const glyph = icon ?? (color === "error" ? "circle-alert" : color === "warning" ? "triangle-alert" : color === "success" ? "circle-check" : "info");
  return (
    <div role={role} className={cx("flex gap-2.5 rounded-md border p-3 text-sm", color === "neutral" ? "border-line bg-subtle" : "border-current/25", color !== "neutral" && SOFT[color].split(" ").filter((c) => !c.startsWith("hover:")).join(" "), className)}>
      <Icon name={glyph} className="mt-0.5 size-4" />
      <div className="min-w-0 space-y-1">
        {title ? <p className="font-medium">{title}</p> : null}
        {description ? <div className={color === "neutral" ? "text-muted" : undefined}>{description}</div> : null}
        {children}
      </div>
    </div>
  );
}

export function Badge({ color = "neutral", icon, children, className, title }: { color?: Color; icon?: string; children?: ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={cx("inline-flex items-center gap-1 whitespace-nowrap rounded-md px-1.5 py-0.5 text-xs font-medium", SOFT[color].split(" ").filter((c) => !c.startsWith("hover:")).join(" "), className)}>
      {icon ? <Icon name={icon} className="size-3.5" /> : null}
      {children}
    </span>
  );
}

export function Field({ label, htmlFor, hint, help, error, required, children, className }: { label: ReactNode; htmlFor: string; hint?: ReactNode; help?: ReactNode; error?: ReactNode; required?: boolean; children: ReactNode; className?: string }) {
  return (
    <div className={cx("space-y-1", className)}>
      <div className="flex items-baseline justify-between gap-2">
        <label htmlFor={htmlFor} className="text-sm font-medium text-strong">{label}{required ? <span aria-hidden="true" className="text-error"> *</span> : null}</label>
        {hint ? <span className="text-xs text-muted">{hint}</span> : null}
      </div>
      {children}
      {help ? <p className="text-xs text-muted">{help}</p> : null}
      {error ? <p className="text-xs text-error" role="alert">{error}</p> : null}
    </div>
  );
}

const INPUT = "block w-full rounded-md border border-line-strong bg-canvas px-2.5 py-1.5 text-sm text-strong placeholder:text-dimmed disabled:opacity-60";
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...rest }, ref) {
  return <input ref={ref} className={cx(INPUT, className)} {...rest} />;
});
export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea({ className, ...rest }, ref) {
  return <textarea ref={ref} className={cx(INPUT, className)} {...rest} />;
});

export function Checkbox({ id, checked, onChange, label, description, disabled }: { id: string; checked: boolean; onChange: (v: boolean) => void; label: ReactNode; description?: ReactNode; disabled?: boolean }) {
  return (
    <div className="flex items-start gap-2">
      <input id={id} type="checkbox" role="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 size-4 accent-[var(--s-primary)]" />
      <div className="text-sm">
        <label htmlFor={id} className="font-medium text-strong">{label}</label>
        {description ? <p className="text-muted">{description}</p> : null}
      </div>
    </div>
  );
}

export function Card({ title, titleId, description, actions, children, className }: { title?: ReactNode; titleId?: string; description?: ReactNode; actions?: ReactNode; children?: ReactNode; className?: string }) {
  return (
    <section aria-labelledby={titleId} className={cx("rounded-lg border border-line bg-canvas", className)}>
      {title ? (
        <header className="flex flex-wrap items-start justify-between gap-2 border-b border-line px-4 py-3">
          <div>
            <h2 id={titleId} className="font-semibold text-strong">{title}</h2>
            {description ? <p className="text-sm text-muted">{description}</p> : null}
          </div>
          {actions}
        </header>
      ) : null}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Empty({ icon, title, description, actions, headingLevel = 2 }: { icon?: string; title: string; description?: ReactNode; actions?: ReactNode; headingLevel?: 1 | 2 | 3 }) {
  const H = `h${headingLevel}` as "h1";
  return (
    <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-line-strong px-6 py-10 text-center">
      {icon ? <Icon name={icon} className="size-8 text-dimmed" /> : null}
      <H className="text-base font-semibold text-strong">{title}</H>
      {description ? <p className="max-w-prose text-sm text-muted">{description}</p> : null}
      {actions ? <div className="mt-2 flex flex-wrap justify-center gap-2">{actions}</div> : null}
    </div>
  );
}

export const TABLE = "w-full text-sm [&_th]:px-3 [&_th]:py-2 [&_th]:text-left [&_th]:font-medium [&_th]:text-muted [&_td]:px-3 [&_td]:py-2 [&_td]:align-top [&_tbody_tr]:border-t [&_tbody_tr]:border-line";
export function Table({ caption, children, className }: { caption?: string; children: ReactNode; className?: string }) {
  return (
    <div className={cx("overflow-x-auto rounded-lg border border-line", className)}>
      <table className={TABLE}>
        {caption ? <caption className="sr">{caption}</caption> : null}
        {children}
      </table>
    </div>
  );
}

// --- select (React Aria): a button that opens a listbox; options are role=option ---
export interface SelectItem { value: string; label: string; description?: string; icon?: string }
export interface SelectGroup { label?: string; items: SelectItem[] }
export function Select({ id, label, ariaLabel, value, onChange, items, groups, placeholder, icon, className, isDisabled, labelHidden }: {
  id?: string; label?: string; ariaLabel?: string; value: string | null | undefined; onChange: (v: string) => void; items?: SelectItem[]; groups?: SelectGroup[];
  placeholder?: string; icon?: string; className?: string; isDisabled?: boolean; labelHidden?: boolean;
}) {
  const all = groups ?? [{ items: items ?? [] }];
  const find = all.flatMap((g) => g.items).find((i) => i.value === value);
  return (
    <AriaSelect selectedKey={value ?? null} onSelectionChange={(k) => k !== null && onChange(String(k))} isDisabled={isDisabled}
      aria-label={label ? undefined : ariaLabel} placeholder={placeholder} className={cx("space-y-1", className)}>
      {label ? <Label className={labelHidden ? "sr" : "block text-sm font-medium text-strong"}>{label}</Label> : null}
      <AriaButton id={id} aria-label={ariaLabel} className={cx(INPUT, "flex items-center gap-2 text-left cursor-pointer")}>
        {icon || find?.icon ? <Icon name={(find?.icon ?? icon)!} className="size-4 text-muted" /> : null}
        <SelectValue className="flex-1 truncate">{({ isPlaceholder }) => (isPlaceholder ? <span className="text-dimmed">{placeholder}</span> : find?.label)}</SelectValue>
        <Icon name="chevrons-up-down" className="size-4 text-dimmed" />
      </AriaButton>
      <Popover className="min-w-(--trigger-width) max-h-80 overflow-auto rounded-md border border-line bg-canvas p-1 shadow-lg">
        <ListBox className="outline-none">
          {all.map((g, gi) => (
            <ListBoxSection key={gi} className="[&+&]:mt-1 [&+&]:border-t [&+&]:border-line [&+&]:pt-1">
              {g.label ? <Header className="px-2 py-1 text-xs font-semibold text-muted">{g.label}</Header> : null}
              {g.items.map((i) => (
                <ListBoxItem key={i.value} id={i.value} textValue={i.label}
                  className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm text-fg outline-none data-[focused]:bg-elevated data-[selected]:font-semibold">
                  {i.icon ? <Icon name={i.icon} className="size-4 text-muted" /> : null}
                  <span className="flex-1">
                    <span className="block">{i.label}</span>
                    {i.description ? <span className="block text-xs text-muted">{i.description}</span> : null}
                  </span>
                </ListBoxItem>
              ))}
            </ListBoxSection>
          ))}
        </ListBox>
      </Popover>
    </AriaSelect>
  );
}

// --- menu (React Aria) ---
export interface MenuEntry { label: string; icon?: string; onAction?: () => void; href?: string; kind?: "label" }
export function DropdownMenu({ trigger, sections, ariaLabel }: { trigger: ReactNode; sections: MenuEntry[][]; ariaLabel: string }) {
  return (
    <MenuTrigger>
      {trigger}
      <Popover placement="top" className="w-56 rounded-md border border-line bg-canvas p-1 shadow-lg">
        <Menu aria-label={ariaLabel} className="outline-none">
          {sections.map((s, si) => (
            <MenuSection key={si}>
              {si > 0 ? <Separator className="my-1 border-t border-line" /> : null}
              {s.map((e) => e.kind === "label"
                ? <Header key={e.label} className="flex items-center gap-2 px-2 py-1.5 text-sm font-semibold text-strong">{e.icon ? <Icon name={e.icon} /> : null}{e.label}</Header>
                : (
                  <MenuItem key={e.label} id={e.label} href={e.href} onAction={e.onAction} textValue={e.label}
                    className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm text-fg outline-none data-[focused]:bg-elevated">
                    {e.icon ? <Icon name={e.icon} className="size-4 text-muted" /> : null}{e.label}
                  </MenuItem>
                ))}
            </MenuSection>
          ))}
        </Menu>
      </Popover>
    </MenuTrigger>
  );
}
export { AriaButton };

// --- modal dialog (React Aria): focus is trapped, Escape closes unless the dialog says otherwise ---
export function DialogModal({ isOpen, onClose, title, description, children, dismissable = true, footer, wide }: {
  isOpen: boolean; onClose: () => void; title: string; description?: ReactNode; children?: ReactNode; dismissable?: boolean; footer?: ReactNode; wide?: boolean;
}) {
  return (
    <ModalOverlay isOpen={isOpen} onOpenChange={(open) => { if (!open) onClose(); }} isDismissable={dismissable} isKeyboardDismissDisabled={!dismissable}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <Modal className={cx("w-full rounded-lg border border-line bg-canvas shadow-xl", wide ? "max-w-2xl" : "max-w-md")}>
        <Dialog className="outline-none">
          <div className="space-y-1 border-b border-line px-4 py-3">
            <Heading slot="title" className="text-base font-semibold text-strong">{title}</Heading>
            {description ? <div className="text-sm text-muted">{description}</div> : null}
          </div>
          {children ? <div className="space-y-4 px-4 py-3">{children}</div> : null}
          {footer ? <div className="flex flex-wrap justify-end gap-2 border-t border-line px-4 py-3">{footer}</div> : null}
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}

/** A clock that ticks only in the browser; the first render uses null so server and browser agree. */
export function useNow(ms = 15000): number | null {
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => { setNow(Date.now()); const t = setInterval(() => setNow(Date.now()), ms); return () => clearInterval(t); }, [ms]);
  return now;
}

export function useInterval(fn: () => void, ms: number) {
  const saved = useRef(fn);
  saved.current = fn;
  useEffect(() => {
    const t = setInterval(() => { if (document.visibilityState === "visible") saved.current(); }, ms);
    return () => clearInterval(t);
  }, [ms]);
}
