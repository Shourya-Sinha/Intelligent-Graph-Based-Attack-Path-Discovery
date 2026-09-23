import { useEffect, useRef } from 'react'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
cytoscape.use(dagre)

const typeColor = {
  entry: "#22d3ee",
  host: "#38bdf8",
  service: "#a78bfa",
  vulnerability: "#f43f5e",
  privilege: "#f97316",
  user: "#eab308",
  data: "#ef4444",
  external: "#64748b"
}
const sevBorder = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#64748b"
}

export default function AttackGraph({ graph, onSelectNode, highlightPath }){
  const ref = useRef(null)
  const cyRef = useRef(null)

  useEffect(()=>{
    if(!graph || !ref.current) return
    const elements = [
      ...graph.nodes.map(n=>({
        data: { id: n.id, label: n.label, type: n.type, severity: n.severity, cvss: n.cvss },
        position: n.x && n.y ? {x: n.x, y: n.y} : undefined
      })),
      ...graph.edges.map(e=>({
        data: { id: e.id, source: e.source, target: e.target, label: e.label, weight: e.weight, exploitability: e.exploitability }
      }))
    ]
    const cy = cytoscape({
      container: ref.current,
      elements,
      style: [
        { selector: 'node', style: {
          'label':'data(label)',
          'text-valign':'center',
          'text-halign':'center',
          'color':'#e2e8f0',
          'font-size': '9px',
          'font-weight': 700,
          'text-wrap':'wrap',
          'text-max-width':'90px',
          'width': 42, 'height': 42,
          'background-color': (ele)=> typeColor[ele.data('type')] || '#334155',
          'border-width': (ele)=> ele.data('severity')? 3:1,
          'border-color': (ele)=> sevBorder[ele.data('severity')] || '#1e293b',
          'shadow-blur': 14, 'shadow-color': '#0ea5e9', 'shadow-opacity': 0.35
        }},
        { selector: 'node[type="data"]', style: { 'shape':'diamond', 'width': 56, 'height': 56 }},
        { selector: 'node[type="entry"]', style: { 'shape':'round-rectangle', 'width': 66, 'height': 34, 'background-color':'#0ea5e9' }},
        { selector: 'edge', style: {
          'width': (ele)=> Math.max(1.5, ele.data('weight')||1),
          'line-color':'#1e293b',
          'target-arrow-color':'#38bdf8',
          'target-arrow-shape':'triangle',
          'curve-style':'bezier',
          'label':'data(label)',
          'font-size':'7px',
          'color':'#94a3b8',
          'text-background-color':'#020617',
          'text-background-opacity':0.9,
          'text-background-padding':2
        }},
        { selector: '.highlight', style: { 'line-color':'#f43f5e', 'target-arrow-color':'#f43f5e', 'width':4, 'shadow-blur':12, 'shadow-color':'#ef4444' }},
        { selector: '.dim', style: { 'opacity':0.25 }}
      ],
      layout: { name: 'dagre', rankDir: 'LR', nodeSep: 30, rankSep: 90, animate: true, animationDuration: 600 }
    })
    cy.on('tap','node', evt=> onSelectNode?.(evt.target.data()))
    cyRef.current = cy
    const resize = ()=> cy.resize()
    window.addEventListener('resize', resize)
    return ()=> { window.removeEventListener('resize', resize); cy.destroy() }
  }, [graph])

  useEffect(()=>{
    const cy = cyRef.current
    if(!cy || !highlightPath) return
    cy.elements().removeClass('highlight dim')
    if(highlightPath.length===0) return
    const pathSet = new Set(highlightPath)
    // dim others
    cy.nodes().forEach(n=>{ if(!pathSet.has(n.id())) n.addClass('dim') })
    // highlight path edges
    for(let i=0;i<highlightPath.length-1;i++){
      const src = highlightPath[i], tgt = highlightPath[i+1]
      const edge = cy.edges(`[source = "${src}"][target = "${tgt}"]`)
      edge.addClass('highlight')
      cy.getElementById(src).removeClass('dim')
      cy.getElementById(tgt).removeClass('dim')
    }
  }, [highlightPath])

  return <div ref={ref} className="w-full h-[520px] bg-[#020617] rounded-xl border border-slate-800 overflow-hidden" />
}
