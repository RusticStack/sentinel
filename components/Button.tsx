import type { ComponentChildren, JSX } from "preact";

export type ButtonVariant = "primary" | "secondary" | "ghost";

const variantClass: Record<ButtonVariant, string> = {
  primary:
    "bg-accent text-accent-ink hover:bg-accent-hover border border-transparent",
  secondary:
    "border border-border bg-surface-2/70 text-fg hover:border-accent-muted hover:bg-accent-soft",
  ghost:
    "border border-transparent text-muted hover:bg-surface-2/50 hover:text-fg",
};

type CommonProps = {
  variant?: ButtonVariant;
  children: ComponentChildren;
  class?: string;
};

export type ButtonAsLink = CommonProps & {
  href: string;
  type?: never;
} & Omit<JSX.HTMLAttributes<HTMLAnchorElement>, "class" | "children" | "href">;

export type ButtonAsButton =
  & CommonProps
  & {
    href?: undefined;
    type?: "button" | "submit" | "reset";
    disabled?: boolean;
  }
  & Omit<
    JSX.HTMLAttributes<HTMLButtonElement>,
    "class" | "children" | "type" | "disabled"
  >;

export type ButtonProps = ButtonAsLink | ButtonAsButton;

function classesFor(
  variant: ButtonVariant,
  className: string | undefined,
): string {
  return `inline-flex items-center justify-center gap-2 rounded-md px-3.5 py-2 font-sans text-sm font-semibold transition-colors ${
    variantClass[variant]
  } ${className ?? ""}`.trim();
}

/** Lemon primary / glass secondary controls: native `<a>` or `<button>`. */
export function Button(props: ButtonProps) {
  const variant = props.variant ?? "primary";
  const classes = classesFor(variant, props.class);

  if (props.href != null) {
    const {
      href,
      children,
      class: _c,
      variant: _v,
      type: _t,
      ...anchorRest
    } = props;
    return (
      <a href={href} class={classes} {...anchorRest}>
        {children}
      </a>
    );
  }

  const {
    children,
    class: _c,
    variant: _v,
    type = "button",
    disabled,
    ...buttonRest
  } = props;
  return (
    <button type={type} class={classes} disabled={disabled} {...buttonRest}>
      {children}
    </button>
  );
}
