// The interface's building blocks: native elements styled with Tailwind, and three small ARIA widgets where the
// platform has no styleable equivalent (a listbox select, a menu button, a modal dialog on the native <dialog>).
// React Aria Components was the first candidate; U09 measured it at about 70 KB of gzipped browser JavaScript for
// these three patterns, more than the whole run page may add under the U14 budget, so they are written here.
import { forwardRef, useEffect, useId, useLayoutEffect, useRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type KeyboardEvent, type ReactNode, type TextareaHTMLAttributes } from "react";
import { Link } from "@tanstack/react-router";
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

// --- shared popup behaviour: closes on a press outside the widget ---
function useOutside(open: boolean, box: React.RefObject<HTMLElement | null>, close: () => void) {
  const latest = useRef(close);
  latest.current = close;
  useEffect(() => {
    if (!open) return;
    const down = (e: PointerEvent) => { if (box.current && !box.current.contains(e.target as Node)) latest.current(); };
    document.addEventListener("pointerdown", down, true);
    return () => document.removeEventListener("pointerdown", down, true);
  }, [open, box]);
}

// --- popups are fixed to the viewport beside their trigger, so a table's scroll box never clips them ---
function usePlacement(open: boolean, anchor: React.RefObject<HTMLElement | null>, prefer: "below" | "above") {
  const [style, setStyle] = useState<React.CSSProperties>({});
  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      const r = anchor.current?.getBoundingClientRect();
      if (!r) return;
      const room = { below: window.innerHeight - r.bottom, above: r.top };
      const above = prefer === "above" ? room.above > 160 || room.above > room.below : room.below < 200 && room.above > room.below;
      const left = Math.max(8, Math.min(r.left, window.innerWidth - 8 - Math.max(r.width, 160)));
      setStyle(above
        ? { position: "fixed", left, bottom: window.innerHeight - r.top + 4, minWidth: r.width, maxHeight: Math.max(120, room.above - 12) }
        : { position: "fixed", left, top: r.bottom + 4, minWidth: r.width, maxHeight: Math.max(120, room.below - 12) });
    };
    place();
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    return () => { window.removeEventListener("resize", place); window.removeEventListener("scroll", place, true); };
  }, [open, anchor, prefer]);
  return style;
}

// --- select: a button that opens a listbox (the ARIA "select-only combobox" pattern; options are role=option) ---
export interface SelectItem { value: string; label: string; description?: string; icon?: string }
export interface SelectGroup { label?: string; items: SelectItem[] }
export function Select({ id, label, ariaLabel, value, onChange, items, groups, placeholder, icon, className, isDisabled, labelHidden }: {
  id?: string; label?: string; ariaLabel?: string; value: string | null | undefined; onChange: (v: string) => void; items?: SelectItem[]; groups?: SelectGroup[];
  placeholder?: string; icon?: string; className?: string; isDisabled?: boolean; labelHidden?: boolean;
}) {
  const auto = useId();
  const triggerId = id ?? `sel-${auto}`;
  const labelId = `${triggerId}-label`;
  const listId = `${triggerId}-list`;
  const all = groups ?? [{ items: items ?? [] }];
  const flat = all.flatMap((g) => g.items);
  const selected = flat.find((i) => i.value === value);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const typed = useRef({ text: "", at: 0 });
  useOutside(open, box, () => setOpen(false));
  const placed = usePlacement(open, trigger, "below");
  useLayoutEffect(() => { if (open) list.current?.focus(); }, [open]);
  useEffect(() => { if (open) document.getElementById(`${listId}-${active}`)?.scrollIntoView({ block: "nearest" }); }, [open, active, listId]);

  const show = (at?: number) => { if (isDisabled || !flat.length) return; setActive(at ?? Math.max(0, flat.findIndex((i) => i.value === value))); setOpen(true); };
  const close = () => { setOpen(false); trigger.current?.focus(); };
  const choose = (i: number) => { const item = flat[i]; setOpen(false); trigger.current?.focus(); if (item && item.value !== value) onChange(item.value); };
  function onTriggerKey(e: KeyboardEvent) {
    if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) { e.preventDefault(); show(); }
  }
  function onListKey(e: KeyboardEvent) {
    const last = flat.length - 1;
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(last, a + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(0, a - 1)); }
    else if (e.key === "Home") { e.preventDefault(); setActive(0); }
    else if (e.key === "End") { e.preventDefault(); setActive(last); }
    else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); choose(active); }
    else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); }
    else if (e.key === "Tab") setOpen(false);
    else if (e.key.length === 1 && /\S/.test(e.key)) {
      // Type-ahead: the next option whose label starts with what was typed in the last 0.7 s.
      const now = Date.now();
      typed.current = { text: (now - typed.current.at < 700 ? typed.current.text : "") + e.key.toLowerCase(), at: now };
      const from = typed.current.text.length > 1 ? active : active + 1;
      const hit = flat.findIndex((i, n) => n >= from && i.label.toLowerCase().startsWith(typed.current.text));
      const wrap = hit >= 0 ? hit : flat.findIndex((i) => i.label.toLowerCase().startsWith(typed.current.text));
      if (wrap >= 0) setActive(wrap);
    }
  }
  let n = -1;
  return (
    <div ref={box} className={cx("relative space-y-1", className)}>
      {label ? <span id={labelId} className={labelHidden ? "sr" : "block text-sm font-medium text-strong"}>{label}</span> : null}
      <button ref={trigger} type="button" id={triggerId} disabled={isDisabled} aria-label={ariaLabel} aria-labelledby={ariaLabel ? undefined : label ? `${labelId} ${triggerId}` : undefined}
        aria-haspopup="listbox" aria-expanded={open} aria-controls={open ? listId : undefined}
        onClick={() => (open ? setOpen(false) : show())} onKeyDown={onTriggerKey}
        className={cx(INPUT, "flex cursor-pointer items-center gap-2 text-left")}>
        {icon || selected?.icon ? <Icon name={(selected?.icon ?? icon)!} className="size-4 text-muted" /> : null}
        <span className="flex-1 truncate">{selected ? selected.label : <span className="text-dimmed">{placeholder ?? "Choose"}</span>}</span>
        <Icon name="chevrons-up-down" className="size-4 text-dimmed" />
      </button>
      {open ? (
        <div ref={list} id={listId} role="listbox" tabIndex={-1} aria-labelledby={label ? labelId : triggerId} aria-activedescendant={`${listId}-${active}`} onKeyDown={onListKey}
          style={placed} className="z-50 w-max max-w-[min(20rem,calc(100vw-1rem))] overflow-auto rounded-md border border-line bg-canvas p-1 shadow-lg outline-none">
          {all.map((g, gi) => (
            <div key={gi} role="group" aria-label={g.label} className={gi ? "mt-1 border-t border-line pt-1" : undefined}>
              {g.label ? <div role="presentation" className="px-2 py-1 text-xs font-semibold text-muted">{g.label}</div> : null}
              {g.items.map((i) => {
                const at = ++n;
                return (
                  <div key={i.value} id={`${listId}-${at}`} role="option" aria-selected={i.value === value}
                    onPointerMove={() => setActive(at)} onClick={() => choose(at)}
                    className={cx("flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm text-fg", at === active && "bg-elevated", i.value === value && "font-semibold")}>
                    {i.icon ? <Icon name={i.icon} className="size-4 text-muted" /> : null}
                    <span className="flex-1">
                      <span className="block">{i.label}</span>
                      {i.description ? <span className="block text-xs text-muted">{i.description}</span> : null}
                    </span>
                    {i.value === value ? <Icon name="check" className="size-4 text-primary" /> : null}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

// --- menu button: a button that opens a menu of actions (role=menu, items role=menuitem) ---
export interface MenuEntry { label: string; icon?: string; onAction?: () => void; kind?: "label" }
export function DropdownMenu({ triggerLabel, trigger, triggerClassName, sections, ariaLabel, placement = "top" }: {
  triggerLabel: string; trigger: ReactNode; triggerClassName?: string; sections: MenuEntry[][]; ariaLabel: string; placement?: "top" | "bottom";
}) {
  const auto = useId();
  const menuId = `menu-${auto}`;
  const [open, setOpen] = useState(false);
  const [focusAt, setFocusAt] = useState<"first" | "last">("first");
  const box = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  useOutside(open, box, () => setOpen(false));
  const placed = usePlacement(open, button, placement === "top" ? "above" : "below");
  const items = () => [...(menu.current?.querySelectorAll<HTMLElement>("[role=menuitem]") ?? [])];
  useLayoutEffect(() => { if (open) { const all = items(); (focusAt === "last" ? all[all.length - 1] : all[0])?.focus(); } }, [open, focusAt]);
  const close = () => { setOpen(false); button.current?.focus(); };
  function onButtonKey(e: KeyboardEvent) {
    if (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ") { e.preventDefault(); setFocusAt("first"); setOpen(true); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setFocusAt("last"); setOpen(true); }
  }
  function onMenuKey(e: KeyboardEvent) {
    const all = items();
    const at = all.indexOf(document.activeElement as HTMLElement);
    if (e.key === "ArrowDown") { e.preventDefault(); all[(at + 1) % all.length]?.focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); all[(at - 1 + all.length) % all.length]?.focus(); }
    else if (e.key === "Home") { e.preventDefault(); all[0]?.focus(); }
    else if (e.key === "End") { e.preventDefault(); all[all.length - 1]?.focus(); }
    else if (e.key === "Escape") { e.preventDefault(); close(); }
    else if (e.key === "Tab") setOpen(false);
  }
  return (
    <div ref={box} className="relative">
      <button ref={button} type="button" aria-label={triggerLabel} aria-haspopup="menu" aria-expanded={open} aria-controls={open ? menuId : undefined}
        onClick={() => { setFocusAt("first"); setOpen((o) => !o); }} onKeyDown={onButtonKey} className={triggerClassName}>
        {trigger}
      </button>
      {open ? (
        <div ref={menu} id={menuId} role="menu" aria-label={ariaLabel} onKeyDown={onMenuKey}
          style={placed} className="z-50 w-56 overflow-auto rounded-md border border-line bg-canvas p-1 shadow-lg">
          {sections.map((s, si) => (
            <div key={si} role="group" className={si ? "mt-1 border-t border-line pt-1" : undefined}>
              {s.map((e) => e.kind === "label"
                ? <div key={e.label} role="presentation" className="flex items-center gap-2 px-2 py-1.5 text-sm font-semibold text-strong">{e.icon ? <Icon name={e.icon} /> : null}{e.label}</div>
                : (
                  <button key={e.label} type="button" role="menuitem" tabIndex={-1} onClick={() => { setOpen(false); button.current?.focus(); e.onAction?.(); }}
                    className="flex w-full cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-left text-sm text-fg hover:bg-elevated focus:bg-elevated">
                    {e.icon ? <Icon name={e.icon} className="size-4 text-muted" /> : null}{e.label}
                  </button>
                ))}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

// --- modal dialog on the native <dialog>: the browser traps focus and makes the page behind it inert ---
export function DialogModal({ isOpen, onClose, title, description, children, dismissable = true, footer, wide }: {
  isOpen: boolean; onClose: () => void; title: string; description?: ReactNode; children?: ReactNode; dismissable?: boolean; footer?: ReactNode; wide?: boolean;
}) {
  const auto = useId();
  const ref = useRef<HTMLDialogElement>(null);
  const latest = useRef({ onClose, dismissable });
  latest.current = { onClose, dismissable };
  useLayoutEffect(() => {
    const d = ref.current;
    if (!isOpen || !d) return;
    const opener = document.activeElement as HTMLElement | null;
    if (!d.open) d.showModal();
    return () => { if (d.open) d.close(); if (opener?.isConnected) opener.focus(); };
  }, [isOpen]);
  if (!isOpen) return null;
  return (
    <dialog ref={ref} role="dialog" aria-modal="true" aria-labelledby={`${auto}-t`} aria-describedby={description ? `${auto}-d` : undefined}
      onCancel={(e) => { e.preventDefault(); if (latest.current.dismissable) latest.current.onClose(); }}
      // A browser may close a dialog on a repeated Escape whatever the page says; one that must stay (shown once) reopens.
      onClose={() => { if (!latest.current.dismissable && ref.current?.isConnected && !ref.current.open) ref.current.showModal(); }}
      onClick={(e) => { if (e.target === ref.current && latest.current.dismissable) latest.current.onClose(); }}
      className={cx("m-auto w-[calc(100vw-2rem)] rounded-lg border border-line bg-canvas p-0 text-fg shadow-xl backdrop:bg-black/50", wide ? "max-w-2xl" : "max-w-md")}>
      <div className="space-y-1 border-b border-line px-4 py-3">
        <h2 id={`${auto}-t`} className="text-base font-semibold text-strong">{title}</h2>
        {description ? <div id={`${auto}-d`} className="text-sm text-muted">{description}</div> : null}
      </div>
      {children ? <div className="space-y-4 px-4 py-3">{children}</div> : null}
      {footer ? <div className="flex flex-wrap justify-end gap-2 border-t border-line px-4 py-3">{footer}</div> : null}
    </dialog>
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
