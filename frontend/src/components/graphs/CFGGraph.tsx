import { useEffect, useMemo, useRef } from 'react';
import * as d3 from 'd3';
import { CFGNode } from '@/types';

export interface CFGGraphNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  kind: string;
  line: number;
  color: string;
  isVulnerable: boolean;
}

export interface CFGGraphLink extends d3.SimulationLinkDatum<CFGGraphNode> {
  source: CFGGraphNode | string;
  target: CFGGraphNode | string;
}

export interface CFGGraphProps {
  nodes: CFGNode[];
  vulnerableLines?: number[];
  height?: number;
  onSelectLine?: (line: number) => void;
}

const TYPE_COLORS: Record<string, string> = {
  ENTRY: '#00FF88',
  EXIT: '#6B7280',
  CONDITION: '#EAB308',
  STATEMENT: '#3B82F6',
  CALL: '#0EA5E9',
  RETURN: '#8B5CF6',
};

function nodeColor(node: CFGNode, vulnerableLines: Set<number>): string {
  if (node.isVulnerable) return '#EF4444';
  if (vulnerableLines.has(node.lineNumber)) return '#F97316';
  return TYPE_COLORS[node.type] ?? '#94A3B8';
}

export function CFGGraph({
  nodes,
  vulnerableLines = [],
  height = 420,
  onSelectLine,
}: CFGGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const vLines = useMemo(() => new Set(vulnerableLines), [vulnerableLines]);

  const graphNodes = useMemo<CFGGraphNode[]>(
    () =>
      nodes.map((n) => ({
        id: n.id,
        label: n.label || n.id,
        kind: n.type,
        line: n.lineNumber,
        color: nodeColor(n, vLines),
        isVulnerable: n.isVulnerable,
      })),
    [nodes, vLines]
  );

  const links = useMemo<Array<{ source: string; target: string }>>(() => {
    const out: Array<{ source: string; target: string }> = [];
    const idSet = new Set(nodes.map((n) => n.id));
    for (const n of nodes) {
      for (const childId of n.children) {
        if (idSet.has(childId)) {
          out.push({ source: n.id, target: childId });
        }
      }
    }
    return out;
  }, [nodes]);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current || graphNodes.length === 0) return;

    const container = containerRef.current;
    const width = container.clientWidth;
    const effectiveHeight = height;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const zoomBehavior = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 2.5])
      .on('zoom', (event) => {
        zoomGroup.attr('transform', event.transform.toString());
      });

    const zoomGroup = svg.append('g');

    svg.call(zoomBehavior);

    const defs = svg.append('defs');
    defs
      .append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 24)
      .attr('refY', 0)
      .attr('markerWidth', 7)
      .attr('markerHeight', 7)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#3A3F4B');

    const simulation = d3
      .forceSimulation<CFGGraphNode>(graphNodes)
      .force(
        'link',
        d3
          .forceLink<CFGGraphNode, { source: string; target: string }>(links)
          .id((d) => d.id)
          .distance(100)
          .strength(0.55)
      )
      .force('charge', d3.forceManyBody().strength(-360))
      .force('center', d3.forceCenter(width / 2, effectiveHeight / 2))
      .force('collide', d3.forceCollide(36));

    const link = zoomGroup
      .append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#3A3F4B')
      .attr('stroke-width', 1.1)
      .attr('stroke-opacity', 0.7)
      .attr('marker-end', 'url(#arrow)');

    link.append('title').text((d) => `${String(d.source)} → ${String(d.target)}`);

    const node = zoomGroup
      .append('g')
      .selectAll('g')
      .data(graphNodes)
      .join('g')
      .style('cursor', 'pointer')
      .on('click', (_event, d) => {
        if (d.line && onSelectLine) onSelectLine(d.line);
      });

    node
      .append('circle')
      .attr('r', 11)
      .attr('fill', (d) => d.color)
      .attr('fill-opacity', 0.18)
      .attr('stroke', (d) => d.color)
      .attr('stroke-width', 1.6);

    node
      .append('text')
      .attr('dy', 4)
      .attr('text-anchor', 'middle')
      .attr('fill', (d) => d.color)
      .style('font-size', '9px')
      .style('font-family', 'monospace')
      .style('font-weight', 'bold')
      .text((d) => (d.kind === 'CONDITION' ? '?' : d.isVulnerable ? '!' : ''));

    node
      .append('text')
      .attr('dy', 30)
      .attr('text-anchor', 'middle')
      .attr('fill', '#E2E8F0')
      .style('font-size', '9px')
      .style('font-family', 'monospace')
      .text((d) => (d.label.length > 26 ? `${d.label.slice(0, 25)}…` : d.label));

    node.append('title').text(
      (d) => `${d.kind} · ${d.label}${d.line ? ` (line ${d.line})` : ''}${d.isVulnerable ? '\nvulnerable' : ''}`
    );

    node
      .append('circle')
      .attr('r', 19)
      .attr('fill', 'transparent')
      .attr('stroke', (d) => d.color)
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', '2 3')
      .style('opacity', 0.5)
      .style('pointer-events', 'none');

    // Keep nodes inside the visible viewport — the unbounded force layout used
    // to push nodes and labels past the container edges.
    const pad = 56;
    const clamp = (v: number | undefined, min: number, max: number) =>
      Math.max(min, Math.min(max, v ?? 0));

    simulation.on('tick', () => {
      link
        .attr('x1', (d) => clamp((d.source as unknown as CFGGraphNode).x, pad, width - pad))
        .attr('y1', (d) => clamp((d.source as unknown as CFGGraphNode).y, pad, effectiveHeight - pad))
        .attr('x2', (d) => clamp((d.target as unknown as CFGGraphNode).x, pad, width - pad))
        .attr('y2', (d) => clamp((d.target as unknown as CFGGraphNode).y, pad, effectiveHeight - pad));

      node.attr('transform', (d) => {
        const x = clamp(d.x, pad, width - pad);
        const y = clamp(d.y, pad, effectiveHeight - pad);
        d.x = x;
        d.y = y;
        return `translate(${x},${y})`;
      });
    });

    // When the layout settles, fit the whole graph into view.
    simulation.on('end', () => {
      const xs = graphNodes.map((d) => d.x ?? 0);
      const ys = graphNodes.map((d) => d.y ?? 0);
      const minX = Math.min(...xs);
      const maxX = Math.max(...xs);
      const minY = Math.min(...ys);
      const maxY = Math.max(...ys);
      const bw = Math.max(1, maxX - minX);
      const bh = Math.max(1, maxY - minY);
      const scale = Math.min((width - 2 * pad) / bw, (effectiveHeight - 2 * pad) / bh, 1.2);
      const tx = width / 2 - scale * ((minX + maxX) / 2);
      const ty = effectiveHeight / 2 - scale * ((minY + maxY) / 2);
      svg.call(zoomBehavior.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
    });

    return () => {
      simulation.stop();
    };
  }, [graphNodes, links, height, onSelectLine]);

  if (nodes.length === 0) {
    return (
      <div className="flex h-[240px] items-center justify-center rounded-xl border border-dashed border-[#2A2D35] text-sm text-textSecondary">
        No control-flow data available for this audit.
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="relative w-full overflow-hidden rounded-xl border border-[#2A2D35] bg-[#0A0B0D]"
    >
      <svg ref={svgRef} width="100%" height={height} />
      <div className="pointer-events-none absolute bottom-3 right-3 flex flex-wrap justify-end gap-x-4 gap-y-1 text-[10px] font-mono text-textSecondary">
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-[#00FF88]" /> entry
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-[#EAB308]" /> condition
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-[#0EA5E9]" /> call
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-[#EF4444]" /> vulnerable
        </span>
      </div>
      <div className="pointer-events-none absolute left-3 top-3 text-[10px] font-mono text-textSecondary">
        click a node to jump to its source line
      </div>
    </div>
  );
}