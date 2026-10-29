// A confirmation before a destructive change: resolves true only when the person picks the action.
import { openOverlay } from "../../lib/overlay.tsx";
import { Button, DialogModal, type Color } from "../ui.tsx";

export function confirmChange({ title, description, action, keep = "Keep", color = "error" }: {
  title: string; description: string; action: string; keep?: string; color?: Color;
}): Promise<boolean> {
  return openOverlay<boolean>((close) => (
    <DialogModal isOpen onClose={() => close(false)} title={title} description={description}
      footer={<>
        <Button color="neutral" variant="ghost" label={keep} onClick={() => close(false)} />
        <Button color={color} label={action} onClick={() => close(true)} />
      </>} />
  ));
}
