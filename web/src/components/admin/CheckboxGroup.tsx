// A row of checkboxes for a list of values (the Vue UCheckboxGroup).
import { Checkbox, cx } from "../ui.tsx";

export function CheckboxGroup({ id, legend, items, value, onChange, error, className }: {
  id: string; legend: string; items: { label: string; value: string }[]; value: string[]; onChange: (next: string[]) => void; error?: string; className?: string;
}) {
  return (
    <fieldset className="space-y-1">
      <legend className="text-sm font-medium text-strong">{legend}</legend>
      <div className={cx("flex flex-wrap gap-x-4 gap-y-1 pt-1", className)}>
        {items.map((i) => (
          <Checkbox key={i.value} id={`${id}-${i.value.replace(/[^A-Za-z0-9_-]/g, "-")}`} label={i.label} checked={value.includes(i.value)}
            onChange={(on) => onChange(on ? [...value.filter((v) => v !== i.value), i.value] : value.filter((v) => v !== i.value))} />
        ))}
      </div>
      {error ? <p className="text-xs text-error" role="alert">{error}</p> : null}
    </fieldset>
  );
}
