/* ============================================================
   D3.js Correlation Graph Renderer
   Force-directed graph: Rules → Techniques → APT Groups → CVEs
   ============================================================ */

const NODE_COLORS = {
  rule:      '#603494', // DXC purple
  technique: '#1565c0', // blue
  apt:       '#c62828', // red
  cve:       '#e65100', // orange
  tactic:    '#2e7d32', // green
};

const NODE_SIZES = {
  rule:      12,
  technique: 10,
  apt:       14,
  cve:       9,
  tactic:    8,
};

const WEAK_COLOR    = '#c62828';
const PARTIAL_COLOR = '#f57c00';
const STRONG_COLOR  = '#2e7d32';

/**
 * Render a correlation graph in the given SVG/container element
 * @param {string} containerId  - DOM id of container div
 * @param {Object} graphData    - { nodes: [], links: [] }
 * @param {Function} onNodeClick - callback(node)
 */
export function renderCorrelationGraph(containerId, graphData, onNodeClick) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';

  const W = container.clientWidth  || 900;
  const H = container.clientHeight || 560;

  const svg = d3.select(`#${containerId}`)
    .append('svg')
    .attr('width', W)
    .attr('height', H)
    .style('background', '#fafafa');

  // Arrow markers
  const defs = svg.append('defs');
  for (const [type, color] of Object.entries(NODE_COLORS)) {
    defs.append('marker')
      .attr('id', `arrow-${type}`)
      .attr('viewBox', '0 -4 8 8')
      .attr('refX', 20).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
        .attr('d', 'M0,-4L8,0L0,4')
        .attr('fill', color)
        .attr('opacity', 0.6);
  }

  const g = svg.append('g');

  // Zoom & pan
  svg.call(d3.zoom()
    .scaleExtent([0.2, 4])
    .on('zoom', e => g.attr('transform', e.transform)));

  const sim = d3.forceSimulation(graphData.nodes)
    .force('link',   d3.forceLink(graphData.links)
      .id(d => d.id)
      .distance(d => {
        // Longer distance for same-type hops
        if (d.source.type === 'rule' && d.target.type === 'technique') return 100;
        if (d.source.type === 'technique' && d.target.type === 'apt')   return 120;
        return 80;
      }))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collision', d3.forceCollide().radius(d => NODE_SIZES[d.type] + 8));

  // Links
  const link = g.append('g')
    .selectAll('line')
    .data(graphData.links)
    .join('line')
      .attr('stroke', d => {
        const str = d.strength ?? 0.5;
        if (str < 0.35) return '#ef9a9a';
        if (str < 0.7)  return '#ffcc80';
        return '#a5d6a7';
      })
      .attr('stroke-width', d => 1 + (d.strength ?? 0.5) * 2.5)
      .attr('stroke-opacity', 0.6)
      .attr('marker-end', d => `url(#arrow-${d.target?.type ?? 'technique'})`);

  // Node groups
  const node = g.append('g')
    .selectAll('g')
    .data(graphData.nodes)
    .join('g')
      .attr('class', 'graph-node')
      .style('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }))
      .on('click', (e, d) => { e.stopPropagation(); onNodeClick?.(d); });

  // Node circles
  node.append('circle')
    .attr('r', d => NODE_SIZES[d.type] ?? 8)
    .attr('fill', d => {
      if (d.type === 'rule') {
        if (d.correlationScore < 0.3)  return WEAK_COLOR;
        if (d.correlationScore < 0.65) return PARTIAL_COLOR;
        return STRONG_COLOR;
      }
      return NODE_COLORS[d.type] ?? '#999';
    })
    .attr('stroke', '#fff')
    .attr('stroke-width', 2)
    .attr('opacity', 0.9);

  // Pulse animation for weak rule nodes
  node.filter(d => d.type === 'rule' && d.correlationScore < 0.3)
    .append('circle')
      .attr('r', d => NODE_SIZES[d.type])
      .attr('fill', 'none')
      .attr('stroke', WEAK_COLOR)
      .attr('stroke-width', 2)
      .attr('opacity', 0.6)
      .append('animate')
        .attr('attributeName', 'r')
        .attr('values', `${NODE_SIZES.rule};${NODE_SIZES.rule + 8};${NODE_SIZES.rule}`)
        .attr('dur', '2s')
        .attr('repeatCount', 'indefinite');

  // Node labels
  node.append('text')
    .text(d => truncateLabel(d.label ?? d.id, d.type))
    .attr('x', d => NODE_SIZES[d.type] + 5)
    .attr('y', 4)
    .attr('font-size', '10px')
    .attr('font-family', "'Inter', sans-serif")
    .attr('fill', '#333')
    .attr('pointer-events', 'none');

  // Tooltip on hover
  const tooltip = d3.select('body').append('div')
    .attr('class', 'graph-tooltip')
    .style('position', 'fixed')
    .style('background', '#fff')
    .style('border', '1px solid #e6e6e6')
    .style('border-radius', '8px')
    .style('padding', '10px 14px')
    .style('font-size', '12px')
    .style('font-family', "'Inter', sans-serif")
    .style('box-shadow', '0 4px 20px rgba(0,0,0,0.12)')
    .style('pointer-events', 'none')
    .style('opacity', 0)
    .style('z-index', 9999)
    .style('max-width', '260px');

  node
    .on('mouseenter', (e, d) => {
      tooltip.style('opacity', 1)
        .html(buildTooltip(d))
        .style('left', (e.clientX + 14) + 'px')
        .style('top',  (e.clientY - 10) + 'px');
    })
    .on('mousemove', e => {
      tooltip
        .style('left', (e.clientX + 14) + 'px')
        .style('top',  (e.clientY - 10) + 'px');
    })
    .on('mouseleave', () => tooltip.style('opacity', 0));

  // Simulation tick
  sim.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);
    node.attr('transform', d => `translate(${d.x},${d.y})`);
  });

  // Cleanup on destroy
  return () => {
    sim.stop();
    tooltip.remove();
  };
}

function truncateLabel(text, type) {
  const max = type === 'rule' ? 22 : 18;
  return text && text.length > max ? text.slice(0, max) + '…' : (text ?? '');
}

function buildTooltip(d) {
  const typeLabel = d.type.charAt(0).toUpperCase() + d.type.slice(1);
  const score = d.correlationScore != null
    ? `<div style="margin-top:4px;font-size:11px;color:#603494"><b>Correlation:</b> ${(d.correlationScore * 100).toFixed(0)}%</div>`
    : '';
  const extra = d.type === 'cve' && d.cvss
    ? `<div style="margin-top:4px;font-size:11px;color:#e65100"><b>CVSS:</b> ${d.cvss}</div>` : '';
  return `
    <div style="font-weight:700;margin-bottom:4px;color:${NODE_COLORS[d.type] ?? '#333'}">[${typeLabel}] ${d.label ?? d.id}</div>
    ${d.description ? `<div style="color:#555;font-size:11px">${d.description.slice(0, 120)}${d.description.length > 120 ? '…' : ''}</div>` : ''}
    ${score}${extra}
  `;
}

/**
 * Build graph data from correlation results
 */
export function buildGraphData(correlationResults) {
  const nodes = [];
  const links = [];
  const nodeSet = new Set();

  function addNode(node) {
    if (!nodeSet.has(node.id)) {
      nodeSet.add(node.id);
      nodes.push(node);
    }
  }

  for (const result of correlationResults) {
    const ruleNode = {
      id:              `rule:${result.rule.id}`,
      type:            'rule',
      label:           result.rule.name,
      description:     result.rule.description,
      correlationScore: result.overallScore,
      rule:            result.rule,
    };
    addNode(ruleNode);

    // Technique nodes
    for (const tech of result.matchedTechniques) {
      const techNode = {
        id:          `tech:${tech.id}`,
        type:        'technique',
        label:       tech.id,
        description: tech.name,
      };
      addNode(techNode);
      links.push({
        source:   ruleNode.id,
        target:   techNode.id,
        strength: result.overallScore,
        type:     'rule-technique',
      });

      // APT nodes
      for (const apt of (tech.aptGroups ?? [])) {
        const aptNode = {
          id:          `apt:${apt.id}`,
          type:        'apt',
          label:       apt.name,
          description: `APT Group • ${apt.techniqueCount ?? 0} TTPs`,
        };
        addNode(aptNode);
        links.push({
          source:   techNode.id,
          target:   aptNode.id,
          strength: 0.7,
          type:     'technique-apt',
        });
      }
    }

    // CVE nodes
    for (const cve of result.matchedCves) {
      const cveNode = {
        id:          `cve:${cve.id}`,
        type:        'cve',
        label:       cve.id,
        description: cve.description?.slice(0, 80),
        cvss:        cve.score,
      };
      addNode(cveNode);
      links.push({
        source:   ruleNode.id,
        target:   cveNode.id,
        strength: cve.score ? cve.score / 10 : 0.4,
        type:     'rule-cve',
      });
    }
  }

  return { nodes, links };
}
