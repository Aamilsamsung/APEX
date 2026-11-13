import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Background, Controls, Handle, Position, ReactFlow, useReactFlow } from '@xyflow/react';
import '@xyflow/react/dist/style.css';

function CertificateNode({ data }) {
  return <div className={'map-node ' + data.tone}>
    {data.incoming && <Handle type="target" position={data.incoming} isConnectable={false} />}
    <small>{data.label}</small>
    <strong>{data.title}</strong>
    <span>{data.detail}</span>
    {data.outgoing && <Handle type="source" position={data.outgoing} isConnectable={false} />}
  </div>;
}

const nodeTypes = { certificate: CertificateNode };

function FitMap({ vertical }) {
  const { fitView } = useReactFlow();
  useEffect(() => {
    const frame = requestAnimationFrame(() => fitView({ padding: 0.22, maxZoom: 1.1 }));
    return () => cancelAnimationFrame(frame);
  }, [vertical, fitView]);
  return null;
}

function CertificateMap({ cert, findings }) {
  const [vertical, setVertical] = useState(() => matchMedia('(max-width: 820px)').matches);
  const [motion, setMotion] = useState(() => !matchMedia('(prefers-reduced-motion: reduce)').matches);
  useEffect(() => {
    const viewport = matchMedia('(max-width: 820px)');
    const preference = matchMedia('(prefers-reduced-motion: reduce)');
    const resize = event => setVertical(event.matches);
    const reduce = event => setMotion(!event.matches);
    viewport.addEventListener('change', resize);
    preference.addEventListener('change', reduce);
    return () => {
      viewport.removeEventListener('change', resize);
      preference.removeEventListener('change', reduce);
    };
  }, []);
  if (!cert) return <div className="map-empty">Certificate data will appear here when available.</div>;
  const tone = findings.some(f => f.severity === 'critical') ? 'danger' : findings.length ? 'caution' : 'healthy';
  const issuer = cert.issuer.replace(/^CN=/, '');
  const items = [
    { id: 'issuer', label: 'Certificate issuer', title: issuer, detail: cert.chain_valid ? 'Sandbox chain verified' : 'Chain validation failed', tone: cert.chain_valid ? 'neutral' : 'danger' },
    { id: 'cert', label: 'Active certificate', title: cert.key_type + ' ' + cert.key_bits, detail: findings.length ? findings.length + ' open findings' : 'No open findings', tone },
    { id: 'service', label: 'Registered service', title: cert.hostname, detail: 'Sandbox inventory', tone },
  ];
  const nodes = items.map((item, index) => ({
    id: item.id, type: 'certificate', draggable: false, selectable: false,
    position: vertical ? { x: 0, y: index * 111 } : { x: index * 252, y: 0 },
    data: {
      ...item,
      incoming: index ? (vertical ? Position.Top : Position.Left) : null,
      outgoing: index < 2 ? (vertical ? Position.Bottom : Position.Right) : null,
    },
  }));
  const edges = [
    { id: 'issuance', source: 'issuer', target: 'cert', style: { stroke: '#7284aa', strokeWidth: 2 } },
    { id: 'registration', source: 'cert', target: 'service', animated: motion, style: {
      stroke: { danger: '#ff8b94', caution: '#f4c17b', healthy: '#76deb2' }[tone], strokeWidth: 2,
    } },
  ];
  return <ReactFlow key={String(vertical)} nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView
    fitViewOptions={{ padding: 0.22, maxZoom: 1.1 }} nodesConnectable={false} elementsSelectable={false}
    minZoom={0.4} maxZoom={2} zoomOnScroll={false} proOptions={{ hideAttribution: true }}>
    <Background gap={19} size={1.2} color="#303443" />
    <Controls showInteractive={false} position="bottom-right" />
    <FitMap vertical={vertical} />
  </ReactFlow>;
}

const root = createRoot(document.getElementById('certificate-map'));
window.renderCertificateMap = (cert, findings) => root.render(<CertificateMap cert={cert} findings={findings} />);
