import { renderToStaticMarkup } from "react-dom/server";
import { Badge } from "./spectrum/badge";
import { Card, CardContent, CardHeader, CardTitle } from "./spectrum/card";

const pages = [
  ["overview", "Overview"],
  ["inventory", "Certificate inventory"],
  ["findings", "Risk findings"],
  ["incidents", "Incident response"],
  ["audit", "Audit trail"],
] as const;

export const navigation = renderToStaticMarkup(
  <nav aria-label="PKI operations">
    {pages.map(([id, title]) => <button key={id} type="button"
      className={id === "overview" ? "nav active" : "nav"} data-tab={id}
      aria-current={id === "overview" ? "page" : undefined}>{title}</button>)}
  </nav>,
);

function Metric({ title, children }: { title: string; children: React.ReactNode }) {
  return <Card className="console-metric">
    <CardHeader><CardTitle>{title}</CardTitle></CardHeader>
    <CardContent>{children}</CardContent>
  </Card>;
}

export const overview = renderToStaticMarkup(
  <div className="console-metrics" aria-label="Certificate summary">
    <Metric title="Certificate health">
      <div className="health-gauge" id="health-gauge" role="img" aria-label="Certificate health loading">
        <svg viewBox="0 0 120 120" aria-hidden="true">
          <circle className="health-track" cx="60" cy="60" r="51"/>
          <circle className="health-fill" id="health-fill" cx="60" cy="60" r="51" pathLength="100"/>
        </svg>
        <div className="health-value" aria-hidden="true"><strong id="health">—</strong><span>%</span></div>
      </div>
      <p id="score-status">Checking certificate health</p>
    </Metric>
    <Metric title="Managed certificates">
      <strong id="total">—</strong>
      <p><span id="healthy">—</span> healthy</p>
      <button type="button" data-goto="inventory" className="textbtn">Open inventory</button>
    </Metric>
    <Metric title="Critical findings">
      <strong id="critical">—</strong>
      <p id="critical-status">Checking risk engine</p>
      <button type="button" data-goto="findings" className="textbtn">Review findings</button>
    </Metric>
    <Metric title="Other findings">
      <strong id="warnings">—</strong>
      <p>High, medium and low severity</p>
    </Metric>
    <div className="console-overview-actions">
      <Badge className="console-sandbox" variant="outline">Sandbox</Badge>
      <button type="button" className="secondary" id="simulate">Simulate incident</button>
    </div>
  </div>,
);
