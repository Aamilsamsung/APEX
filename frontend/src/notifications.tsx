import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { createRoot } from "react-dom/client";
import { Badge } from "./spectrum/badge";
import { Popover, PopoverContent, PopoverTrigger } from "./spectrum/popover";

interface Incident {
  id: string;
  type: string;
  status: string;
}

function label(incident: Incident) {
  switch (incident.status) {
    case "pending_approval": return "Approval required";
    case "resolved":
    case "acme_recovery_worker_verified": return "Incident resolved";
    case "rejected": return "Remediation rejected";
    case "failed": return "Remediation failed";
    default: return "Incident updated";
  }
}

function Notifications() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [toast, setToast] = useState<Incident>();
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState("Loading notifications…");
  const previous = useRef<Map<string, string> | undefined>(undefined);
  const pending = incidents.filter(incident => incident.status === "pending_approval").length;

  useEffect(() => {
    const controller = new AbortController();
    let busy = false;
    async function refresh() {
      if (busy || document.hidden) return;
      busy = true;
      try {
        const response = await fetch("/api/incidents", {
          cache: "no-store",
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(10000)]),
        });
        if (!response.ok) throw new Error("Incident refresh failed");
        const items: Incident[] = await response.json();
        if (!Array.isArray(items)) throw new Error("Invalid incident list");
        const prior = previous.current;
        const changed = prior
          ? items.find(item => prior.has(item.id) && prior.get(item.id) !== item.status)
            ?? items.find(item => !prior.has(item.id))
          : items.find(item => item.status === "pending_approval");
        previous.current = new Map(items.map(item => [item.id, item.status]));
        if (changed) setToast(changed);
        setIncidents(items);
        setStatus("");
      } catch {
        if (!controller.signal.aborted) setStatus("Unable to refresh notifications.");
      } finally {
        busy = false;
      }
    }

    void refresh();
    const timer = window.setInterval(refresh, 12000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      controller.abort();
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, []);

  function review(id: string) {
    setOpen(false);
    setToast(undefined);
    window.dispatchEvent(new CustomEvent("aegis:review-incident", { detail: id }));
  }

  return <>
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button className="apex-alert-bell" type="button" aria-label={`Notifications, ${pending} pending approvals`}>
          <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
            <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          {pending > 0 && <Badge className="apex-alert-count" variant="destructive" aria-hidden="true">{pending > 9 ? "9+" : pending}</Badge>}
        </button>
      </PopoverTrigger>
      <PopoverContent className="apex-alert-panel" align="end" sideOffset={8} collisionPadding={12}
        aria-label="Incident notifications" onCloseAutoFocus={event => {
          if (document.activeElement?.closest(".incident-card")) event.preventDefault();
        }}>
        <h2>Notifications</h2>
        {status && <p role="status">{status}</p>}
        {!status && !incidents.length && <p>No incidents yet.</p>}
        {incidents.slice(0, 12).map(incident => <div className="apex-alert-item" key={incident.id}>
          <strong>{label(incident)}</strong>
          <p>{incident.type} · {incident.id}</p>
          <button type="button" onClick={() => review(incident.id)}>View incident</button>
        </div>)}
      </PopoverContent>
    </Popover>
    {toast && createPortal(
      <section className="apex-alert-toast" aria-label="Incident notification">
        <button type="button" className="apex-alert-close" aria-label="Dismiss notification" onClick={() => setToast(undefined)}>×</button>
        <div role="status"><h2>{label(toast)}</h2><p>{toast.type} · {toast.id}</p></div>
        <button type="button" onClick={() => review(toast.id)}>Review incident</button>
      </section>,
      document.body,
    )}
  </>;
}

const mount = document.getElementById("apex-alert-root");
if (mount) createRoot(mount).render(<Notifications />);
