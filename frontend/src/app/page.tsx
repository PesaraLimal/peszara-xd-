"use client"

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Monitor, Cpu, HardDrive, ShieldAlert, ArrowRight, RefreshCw, Terminal, Activity, Share2 } from 'lucide-react'

interface Device {
  device_id: string
  hostname: string
  os_name: string
  os_version?: string
  ip_address?: string
  mac_address?: string
  cpu_usage?: number
  ram_usage?: number
  logged_in_user?: string
  risk_score: number
  status: string
  last_seen: string
  dashboard_token?: string
}

export default function Dashboard() {
  const router = useRouter()
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'

  const fetchDevices = async () => {
    try {
      setLoading(true)
      const res = await fetch(`${API_URL}/api/v1/devices`, {
        headers: {
          'Bypass-Tunnel-Reminder': 'true'
        }
      })

      if (!res.ok) throw new Error('Failed to fetch devices')
      const data = await res.json()
      setDevices(data)
      setError(null)
    } catch (err: any) {
      setError(err.message || 'Error connecting to backend')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDevices()
    const timer = setInterval(fetchDevices, 10000) // refresh every 10s
    return () => clearInterval(timer)
  }, [])

  // Dynamic statistics
  const totalDevices = devices.length
  const criticalDevices = devices.filter(d => d.risk_score >= 70).length
  const parseDateSafe = (dateStr: string) => {
    if (!dateStr) return new Date(0)
    if (!dateStr.endsWith('Z') && !/[+-]\d{2}:\d{2}$/.test(dateStr)) {
      return new Date(dateStr + 'Z')
    }
    return new Date(dateStr)
  }

  const onlineDevices = devices.filter(d => {
    const lastSeen = parseDateSafe(d.last_seen).getTime()
    const now = new Date().getTime()
    return (now - lastSeen) < 45000 // online if seen in past 45s
  }).length

  return (
    <div className="flex-1 p-8 max-w-7xl mx-auto w-full">
      {/* Title section */}
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-white mb-2">
            Threat & Endpoint Overview
          </h1>
          <p className="text-cyber-muted text-sm">
            Real-time status of enrolled devices and active threat signatures.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button 
            onClick={fetchDevices}
            className="flex items-center space-x-2 bg-cyber-card border border-cyber-border hover:border-cyber-accent text-cyber-text hover:text-cyber-accent transition px-4 py-2 rounded-md font-mono text-sm"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>REFRESH</span>
          </button>
        </div>
      </div>

      {/* Global Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-[#121824] border border-[#1E293B] rounded-lg p-5 flex items-center justify-between">
          <div>
            <span className="text-xs text-cyber-muted uppercase tracking-wider block font-bold">Total Enrolled Hosts</span>
            <span className="text-3xl font-bold font-mono text-white mt-1 block">{totalDevices}</span>
          </div>
          <div className="w-10 h-10 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center text-slate-400">
            <Monitor size={20} />
          </div>
        </div>

        <div className="bg-[#121824] border border-[#1E293B] rounded-lg p-5 flex items-center justify-between">
          <div>
            <span className="text-xs text-cyber-muted uppercase tracking-wider block font-bold">Online Agents</span>
            <span className="text-3xl font-bold font-mono text-cyber-green mt-1 block">{onlineDevices}</span>
          </div>
          <div className="w-10 h-10 rounded-full bg-emerald-950/40 border border-emerald-900 flex items-center justify-center text-cyber-green">
            <Activity size={20} />
          </div>
        </div>

        <div className="bg-[#121824] border border-[#1E293B] rounded-lg p-5 flex items-center justify-between">
          <div>
            <span className="text-xs text-cyber-muted uppercase tracking-wider block font-bold">Active Threats / Criticals</span>
            <span className="text-3xl font-bold font-mono text-cyber-red mt-1 block">{criticalDevices}</span>
          </div>
          <div className="w-10 h-10 rounded-full bg-rose-950/40 border border-rose-900 flex items-center justify-center text-cyber-red">
            <ShieldAlert size={20} />
          </div>
        </div>

        <div className="bg-[#121824] border border-[#1E293B] rounded-lg p-5 flex items-center justify-between">
          <div>
            <span className="text-xs text-cyber-muted uppercase tracking-wider block font-bold">Average Host Risk</span>
            <span className="text-3xl font-bold font-mono text-cyber-yellow mt-1 block">
              {devices.length ? Math.round(devices.reduce((acc, curr) => acc + curr.risk_score, 0) / devices.length) : 0}%
            </span>
          </div>
          <div className="w-10 h-10 rounded-full bg-amber-950/40 border border-amber-900 flex items-center justify-center text-cyber-yellow">
            <ShieldAlert size={20} />
          </div>
        </div>
      </div>

      {/* Device grid section */}
      {error && (
        <div className="bg-rose-950/30 border border-rose-800 text-rose-300 p-4 rounded-lg mb-8 font-mono text-sm">
          CRITICAL ERROR: Failed to communicate with XDR Backend. Make sure backend is running at {API_URL}.
        </div>
      )}

      {loading && devices.length === 0 ? (
        <div className="h-64 flex flex-col items-center justify-center space-y-4">
          <RefreshCw className="animate-spin text-cyber-accent" size={32} />
          <p className="font-mono text-cyber-muted text-sm">Scanning active telemetry networks...</p>
        </div>
      ) : devices.length === 0 ? (
        <div className="bg-cyber-card border border-cyber-border rounded-lg p-8 text-center max-w-xl mx-auto mt-8">
          <Terminal size={48} className="mx-auto text-cyber-accent mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">No Registered Telemetry Agents</h2>
          <p className="text-cyber-muted text-sm mb-6">
            Peszara XDR is waiting for system telemetry. Follow the instructions to install and register the python agent on an endpoint.
          </p>
          <div className="bg-slate-950 p-4 rounded border border-cyber-border text-left font-mono text-xs text-cyber-green overflow-x-auto space-y-2">
            <div># Setup and start the telemetry agent:</div>
            <div>cd agent</div>
            <div>pip install -r requirements.txt</div>
            <div>python agent.py</div>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {devices.map((device) => {
            const isOnline = (new Date().getTime() - parseDateSafe(device.last_seen).getTime()) < 45000
            const riskColor = 
              device.risk_score >= 70 ? 'text-cyber-red border-rose-900/50 bg-rose-950/10' :
              device.risk_score >= 30 ? 'text-cyber-yellow border-amber-900/50 bg-amber-950/10' :
              'text-cyber-green border-emerald-900/50 bg-emerald-950/10'

            return (
              <div 
                key={device.device_id}
                className="bg-cyber-card border border-cyber-border hover:border-cyber-accent transition-all duration-300 rounded-lg p-6 flex flex-col justify-between"
              >
                <div>
                  {/* Status header */}
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h2 className="text-xl font-bold text-white">{device.hostname}</h2>
                      <span className="font-mono text-xs text-cyber-muted">{device.device_id}</span>
                    </div>
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase font-mono ${
                      isOnline ? 'bg-emerald-950 border border-emerald-800 text-cyber-green' : 'bg-slate-900 border border-slate-700 text-cyber-muted'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${isOnline ? 'bg-cyber-green animate-pulse' : 'bg-slate-500'}`}></span>
                      {isOnline ? 'ONLINE' : 'OFFLINE'}
                    </span>
                  </div>

                  {/* System metadata */}
                  <div className="space-y-2.5 my-5 border-t border-b border-slate-800 py-3 font-mono text-xs text-cyber-muted">
                    <div className="flex justify-between">
                      <span>OS:</span>
                      <span className="text-cyber-text">{device.os_name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>IP:</span>
                      <span className="text-cyber-text">{device.ip_address || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Active User:</span>
                      <span className="text-cyber-text truncate max-w-[150px]">{device.logged_in_user || 'N/A'}</span>
                    </div>
                  </div>

                  {/* Live Stats Indicators */}
                  <div className="grid grid-cols-2 gap-4 mb-6 text-xs font-mono">
                    <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800/80">
                      <div className="flex items-center space-x-1.5 text-cyber-muted mb-1">
                        <Cpu size={12} />
                        <span>CPU Usage</span>
                      </div>
                      <span className="text-white font-bold">{device.cpu_usage ?? 0}%</span>
                    </div>
                    <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800/80">
                      <div className="flex items-center space-x-1.5 text-cyber-muted mb-1">
                        <HardDrive size={12} />
                        <span>RAM Usage</span>
                      </div>
                      <span className="text-white font-bold">{device.ram_usage ?? 0}%</span>
                    </div>
                  </div>
                </div>

                {/* Risk score gauge and redirect button */}
                <div>
                  <div className={`border rounded-lg p-3.5 flex items-center justify-between mb-4 ${riskColor}`}>
                    <div>
                      <span className="text-xs uppercase tracking-wider block font-bold text-cyber-muted">Risk Severity</span>
                      <span className="text-2xl font-bold font-mono">
                        {device.risk_score} <span className="text-xs text-cyber-muted font-normal">/ 100</span>
                      </span>
                    </div>
                    <ShieldAlert size={28} />
                  </div>

                  <div className="flex space-x-2">
                    <Link 
                      href={`/device/${device.device_id}`}
                      className="flex-1 bg-[#1A2536] border border-cyber-border hover:border-cyber-accent text-cyber-text hover:text-cyber-accent flex items-center justify-center space-x-2 py-2.5 rounded-lg text-sm font-semibold transition"
                    >
                      <span>INVESTIGATE HOST</span>
                      <ArrowRight size={14} />
                    </Link>
                    {device.dashboard_token && (
                      <button 
                        onClick={() => {
                          const baseUrl = window.location.origin
                          const shareUrl = `${baseUrl}/device/${device.device_id}?token=${device.dashboard_token}`
                          navigator.clipboard.writeText(shareUrl)
                          alert('Shareable Dashboard Link copied to clipboard!')
                        }}
                        className="bg-[#121824] border border-cyber-border hover:border-cyber-accent text-cyber-muted hover:text-cyber-accent p-2.5 rounded-lg transition"
                        title="Copy Shareable Dashboard Link"
                      >
                        <Share2 size={16} />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
