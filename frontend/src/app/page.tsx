"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Monitor, Cpu, Server, Terminal, ShieldAlert, CheckCircle, RefreshCw, PlusCircle } from "lucide-react";

interface Device {
  id: string;
  hostname: string;
  os_name: string;
  os_version: string;
  ip_address: string;
  mac_address?: string;
  logged_in_user?: string;
  cpu_usage: number;
  memory_usage: number;
  risk_score: number;
  last_seen: string;
}

export default function Home() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const fetchDevices = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/devices");
      if (!res.ok) throw new Error("Could not connect to the XDR backend server.");
      const data = await res.json();
      setDevices(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || "Failed to fetch device registry.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDevices();
    const interval = setInterval(fetchDevices, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchDevices();
  };

  return (
    <main className="min-h-screen bg-[#080a0f] text-[#f3f4f6] font-mono selection:bg-emerald-500 selection:text-black">
      {/* Header */}
      <header className="border-b border-[#1d2433] bg-[#0c0f16]/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8 flex justify-between items-center">
          <div className="flex items-center space-x-3">
            <div className="h-3 w-3 bg-emerald-500 rounded-full animate-ping"></div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white glow-green">
                PESZARA XDR
              </h1>
              <p className="text-xs text-[#9ca3af]">
                AI-Powered Endpoint Security & Telemetry Platform
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
              <span className="w-1.5 h-1.5 mr-1.5 bg-emerald-400 rounded-full pulse-glow"></span>
              SYSTEM ONLINE
            </span>
            <button
              onClick={handleRefresh}
              className={`p-1.5 rounded bg-[#0f131a] hover:bg-[#1d2433] border border-[#1d2433] transition-all text-[#9ca3af] hover:text-white ${
                refreshing ? "animate-spin text-emerald-400" : ""
              }`}
              title="Refresh Registry"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
        {/* Banner */}
        <section className="mb-10 p-6 rounded-lg border border-[#1d2433] bg-[#0f131a] relative overflow-hidden">
          <div className="absolute top-0 right-0 h-64 w-64 bg-emerald-500/5 blur-[80px] rounded-full pointer-events-none"></div>
          <div className="max-w-3xl">
            <span className="text-emerald-400 text-xs font-semibold uppercase tracking-wider block mb-2">
              Cybersecurity Portfolio MVP
            </span>
            <h2 className="text-2xl font-bold text-white mb-2">
              Host Security Auditing & Investigation Hub
            </h2>
            <p className="text-sm text-[#9ca3af] leading-relaxed mb-4">
              Deploy the Python Telemetry Agent to any endpoint to capture raw system activity, map behaviors to MITRE ATT&CK categories, perform automated reputation checks via AbuseIPDB and VirusTotal, and query AI incident analysis pipelines.
            </p>
          </div>
        </section>

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Device List Section */}
          <div className="lg:col-span-2 space-y-6">
            <div className="flex justify-between items-center mb-2">
              <h3 className="text-md font-semibold text-[#9ca3af] uppercase tracking-wider flex items-center space-x-2">
                <Monitor className="h-4 w-4 text-emerald-400" />
                <span>Registered Devices ({devices.length})</span>
              </h3>
            </div>

            {loading ? (
              <div className="p-8 border border-[#1d2433] rounded-lg bg-[#0f131a] flex flex-col items-center justify-center space-y-3">
                <RefreshCw className="h-8 w-8 text-emerald-400 animate-spin" />
                <span className="text-xs text-[#9ca3af]">Loading device registry...</span>
              </div>
            ) : error ? (
              <div className="p-6 border border-red-900/50 rounded-lg bg-red-950/20 text-red-400 flex flex-col space-y-3">
                <ShieldAlert className="h-8 w-8 text-red-500" />
                <div>
                  <h4 className="font-bold text-sm">Server Offline</h4>
                  <p className="text-xs text-red-300 mt-1">{error}</p>
                </div>
                <button
                  onClick={handleRefresh}
                  className="px-3 py-1.5 bg-[#0f131a] border border-[#1d2433] hover:border-red-500 text-xs rounded transition-colors w-fit text-[#f3f4f6]"
                >
                  Retry Connection
                </button>
              </div>
            ) : devices.length === 0 ? (
              <div className="p-10 border border-dashed border-[#1d2433] rounded-lg bg-[#0f131a]/50 text-center flex flex-col items-center justify-center space-y-4">
                <PlusCircle className="h-10 w-10 text-[#9ca3af] animate-pulse" />
                <div>
                  <h4 className="text-sm font-bold text-white">No Endpoints Connected</h4>
                  <p className="text-xs text-[#9ca3af] max-w-sm mx-auto mt-1">
                    Telemetry data stream is currently empty. Run the Python agent on a machine to register it below.
                  </p>
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {devices.map((device) => {
                  const getRiskColor = (score: number) => {
                    if (score >= 70) return "text-red-500 border-red-500/30 bg-red-500/10";
                    if (score >= 40) return "text-yellow-500 border-yellow-500/30 bg-yellow-500/10";
                    return "text-emerald-500 border-emerald-500/30 bg-emerald-500/10";
                  };

                  const getRiskBarColor = (score: number) => {
                    if (score >= 70) return "bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]";
                    if (score >= 40) return "bg-yellow-500 shadow-[0_0_10px_rgba(234,179,8,0.5)]";
                    return "bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]";
                  };

                  return (
                    <div
                      key={device.id}
                      className="p-5 border border-[#1d2433] hover:border-emerald-500/40 rounded-lg bg-[#0f131a] transition-all flex flex-col justify-between"
                    >
                      <div className="mb-4">
                        <div className="flex justify-between items-start">
                          <div>
                            <h4 className="font-bold text-white text-md flex items-center space-x-1.5">
                              <Server className="h-4 w-4 text-[#9ca3af]" />
                              <span>{device.hostname}</span>
                            </h4>
                            <p className="text-[10px] text-[#9ca3af] mt-0.5">
                              ID: {device.id}
                            </p>
                          </div>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${getRiskColor(
                              device.risk_score
                            )}`}
                          >
                            Risk: {device.risk_score}%
                          </span>
                        </div>

                        {/* OS Spec */}
                        <div className="grid grid-cols-2 gap-2 mt-4 text-[11px] text-[#9ca3af]">
                          <div>
                            <span className="text-[10px] text-gray-600 block">OS</span>
                            <span className="text-white font-semibold">{device.os_name}</span>
                          </div>
                          <div>
                            <span className="text-[10px] text-gray-600 block">IP</span>
                            <span className="text-white font-semibold">{device.ip_address}</span>
                          </div>
                          <div>
                            <span className="text-[10px] text-gray-600 block">User</span>
                            <span className="text-white font-semibold truncate block">
                              {device.logged_in_user || "N/A"}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] text-gray-600 block">Last Seen</span>
                            <span className="text-white">
                              {new Date(device.last_seen).toLocaleTimeString()}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Risk Score Meter */}
                      <div className="mb-4">
                        <div className="flex justify-between text-[10px] text-[#9ca3af] mb-1">
                          <span>Endpoint Risk Rating</span>
                          <span className="font-bold">{device.risk_score} / 100</span>
                        </div>
                        <div className="w-full h-1.5 bg-gray-950 rounded overflow-hidden">
                          <div
                            className={`h-full ${getRiskBarColor(device.risk_score)}`}
                            style={{ width: `${device.risk_score}%` }}
                          ></div>
                        </div>
                      </div>

                      <Link
                        href={`/device/${device.id}`}
                        className="w-full py-2 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800 text-emerald-400 hover:text-emerald-300 text-xs font-bold text-center rounded transition-all flex items-center justify-center space-x-1"
                      >
                        <Terminal className="h-3.5 w-3.5" />
                        <span>Inspect Telemetry</span>
                      </Link>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Quick Setup Guide Section */}
          <div className="space-y-6">
            <div className="p-6 border border-[#1d2433] rounded-lg bg-[#0f131a] relative">
              <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4 flex items-center space-x-2">
                <Terminal className="h-4.5 w-4.5 text-emerald-400" />
                <span>Agent Deployment</span>
              </h3>

              <div className="space-y-4 text-xs text-[#9ca3af]">
                <p>
                  To register an endpoint host to the Peszara XDR engine, install the telemetry dependencies and initiate the loop on the host machine.
                </p>

                <div className="space-y-2">
                  <span className="text-white font-bold block">1. Clone & Setup Folder</span>
                  <p className="text-[11px]">Navigate into the agent directory on your host:</p>
                  <pre className="p-2 bg-gray-950 border border-[#1d2433] rounded text-emerald-400 overflow-x-auto text-[10px]">
                    cd ./agent
                  </pre>
                </div>

                <div className="space-y-2">
                  <span className="text-white font-bold block">2. Install Required Libs</span>
                  <pre className="p-2 bg-gray-950 border border-[#1d2433] rounded text-emerald-400 overflow-x-auto text-[10px]">
                    pip install -r requirements.txt
                  </pre>
                </div>

                <div className="space-y-2">
                  <span className="text-white font-bold block">3. Launch Python Loop</span>
                  <pre className="p-2 bg-gray-950 border border-[#1d2433] rounded text-emerald-400 overflow-x-auto text-[10px]">
                    python agent.py
                  </pre>
                </div>

                <div className="p-3 bg-emerald-950/20 border border-emerald-900/50 rounded-lg text-emerald-400 flex items-start space-x-2 text-[11px]">
                  <CheckCircle className="h-4 w-4 mr-1 flex-shrink-0 mt-0.5" />
                  <span>
                    Once launched, the telemetry client registers a MAC-address-tied hash and pushes process updates every 10 seconds.
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
