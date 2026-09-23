import { Component } from 'react'

export default class ErrorBoundary extends Component {
  constructor(p){ super(p); this.state={hasError:false, err:null} }
  static getDerivedStateFromError(err){ return {hasError:true, err} }
  componentDidCatch(err, info){ console.error('UI crash', err, info) }
  render(){
    if(this.state.hasError){
      return (
        <div className="min-h-[40vh] grid place-items-center p-6">
          <div className="glass rounded-2xl p-6 max-w-lg text-center">
            <div className="text-2xl">💥 Something broke — but we recovered</div>
            <div className="text-sm text-slate-400 mt-2 mono whitespace-pre-wrap">{String(this.state.err?.message||this.state.err).slice(0,500)}</div>
            <button onClick={()=>location.reload()} className="mt-4 px-4 py-2 bg-violet-600 hover:bg-violet-500 rounded-xl text-white font-bold">Reload</button>
            <div className="text-xs text-slate-500 mt-2">No data lost — store persists via SQLite if USE_PERSISTENCE=true. Check /api/health</div>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
