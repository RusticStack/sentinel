// Secrets stay in this dialog only: no toast, storage or URL, and they are cleared once the person confirms saving.
import { useEffect, useRef, useState } from "react";
import { openOverlay } from "../lib/overlay.tsx";
import { Button, Checkbox, DialogModal } from "./ui.tsx";

/** `labels` name each value on screen and to assistive technology; the copied and downloaded text stays the bare values. */
export interface ShowOnce { title: string; description: string; secrets: string[]; filename: string; note?: string; labels?: string[] }

export function showOnce(props: ShowOnce): Promise<void> {
  return openOverlay<void>((close) => <ShowOnceDialog {...props} onClose={() => close()} />);
}

function ShowOnceDialog({ title, description, secrets, filename, note, labels, onClose }: ShowOnce & { onClose: () => void }) {
  const [values, setValues] = useState<string[]>([...secrets]);
  const [saved, setSaved] = useState(false);
  const [status, setStatus] = useState("");
  const blob = useRef<string | null>(null);
  const text = () => values.join("\n") + "\n";
  useEffect(() => () => { if (blob.current) URL.revokeObjectURL(blob.current); }, []);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text());
      setStatus(values.length > 1 ? "Copied all to the clipboard." : "Copied to the clipboard.");
    } catch {
      setStatus("The browser refused the clipboard; select the text or download it instead.");
    }
  }
  function download() {
    const url = (blob.current ??= URL.createObjectURL(new Blob([text()], { type: "text/plain" })));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    // The object URL lives until the dialog is gone so the download can finish.
    setStatus(`Downloaded ${filename}.`);
  }
  function done() {
    if (!saved) return;
    setValues([]);
    onClose();
  }

  return (
    <DialogModal isOpen dismissable={false} onClose={() => {}} title={title} description={description} wide={values.length > 1}
      footer={<Button label="Done" disabled={!saved} onClick={done} />}>
      <ul className={values.length > 1 ? "grid grid-cols-1 gap-2 sm:grid-cols-2" : ""} aria-label={title}>
        {values.map((v, i) => labels?.[i] ? (
          <li key={i} className="break-all rounded-md border border-line bg-subtle px-3 py-2">
            <span className="block text-xs text-muted">{labels[i]}</span>
            <span data-secret="" className="select-all font-mono text-sm">{v}</span>
          </li>
        ) : <li key={i} className="select-all break-all rounded-md border border-line bg-subtle px-3 py-2 font-mono text-sm">{v}</li>)}
      </ul>
      {note ? <p className="text-sm text-muted">{note}</p> : null}
      <div className="flex flex-wrap gap-2">
        <Button color="neutral" variant="outline" icon="copy" label="Copy" onClick={copy} />
        <Button color="neutral" variant="outline" icon="download" label="Download" onClick={download} />
      </div>
      <p role="status" aria-live="polite" className="min-h-5 text-sm text-muted">{status}</p>
      <Checkbox id="show-once-saved" checked={saved} onChange={setSaved} label="I have saved this somewhere safe" description="It is not shown again." />
    </DialogModal>
  );
}
