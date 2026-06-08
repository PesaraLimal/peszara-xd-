"use client";

import React, { useEffect, useState, useRef } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ArrowLeft,
  Server,
  ShieldAlert,
  Terminal,
  Activity,
  Network,
  FolderOpen,
  Bot,
  FileText,
  AlertCircle,
  Play,
  RotateCcw,
  CheckCircle,
  Search,
  ExternalLink,
  ChevronRight,
  Cpu
} from "lucide-react";

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

interface Process {
  id: number;
  pid: number;
  ppid?: number;
  name: string;
  exe?: string;
  cmdline?: string;
  username?: string;
  sha256?: string;
}

interface Connection {
  id: number;
  pid?: number;
  process_name?: string;
  family?: string;
  type?: string;
  laddr?: string;
  raddr?: string;
  status?: string;
}

interface FileEvent {
  id: number;
  action: string;
  filepath: string;
  timestamp: string;
}

interface Alert {
  id: number;
  title: string;
  description: string;
  severity: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  status: string;
  created_at: string;
}

interface Investigation {
  id: number;
  summary: string;
  analysis: string;
  remediation: string;
  created_at: string;
}

export default function DeviceDetail() {
  const params = useParams();
  const deviceId = params.device_id as string;

  // Data States
  const [device, setDevice] = useState<Device | null>(null);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [fileEvents, setFileEvents] = useState<FileEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [investigation, setInvestigation] = useState<Investigation | null>(null);

  // UI States
  const [activeTab, setActiveTab] = useState<"alerts" | "processes" | "sockets" | "files" | "ai">("alerts");
  const [searchQuery, setSearchQuery] = useState("");
  const [auditLogs, setAuditLogs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  
  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Add scroll logs helper
  const addAuditLog = (msg: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setAuditLogs((prev) => [...prev, `[${timestamp}] ${msg}`].slice(-30)); // Limit to last 30 logs
  };

  const fetchData = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      // Fetch Device
      const devRes = await fetch(`http://localhost:8000/api/device/${deviceId}`);
      if (!devRes.ok) throw new Error("Device not found");
      const devData = await devRes.json();
      setDevice(devData);

      // Fetch alerts
      const alertsRes = await fetch(`http://localhost:8000/api/device/${deviceId}/alerts`);
      const alertsData = await alertsRes.json();
      setAlerts(alertsData);

      // Fetch processes
      const procRes = await fetch(`http://localhost:8000/api/device/${deviceId}/processes`);
      const procData = await procRes.json();
      setProcesses(procData);

      // Fetch sockets
      const connRes = await fetch(`http://localhost:8000/api/device/${deviceId}/connections`);
      const connData = await connRes.json();
      setConnections(connData);

      // Fetch files
      const filesRes = await fetch(`http://localhost:8000/api/device/${deviceId}/file-events`);
      const filesData = await filesRes.json();
      setFileEvents(filesData);

      // Fetch investigations
      const invsRes = await fetch(`http://localhost:8000/api/device/${deviceId}/investigations`);
      const invsData = await invsRes.json();
      if (invsData.length > 0) {
        setInvestigation(invsData[0]); // Load latest
      }
    } catch (err) {
      console.error(err);
      addAuditLog("Error fetching device telemetries");
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    addAuditLog(`Established session context for Device ID: ${deviceId}`);
    
    // Poll every 5s for telemetry updates
    const interval = setInterval(() => {
      fetchData(true);
    }, 5000);
    return () => clearInterval(interval);
  }, [deviceId]);

  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [auditLogs]);

  // Run Safe check
  const handleSafeCheck = async () => {
    setScanLoading(true);
    addAuditLog("Triggering safe device compliance check...");
    try {
      const res = await fetch(`http://localhost:8000/api/device/${deviceId}/simulate-scan?scan_type=safe`, {
        method: "POST"
      });
      if (res.ok) {
        addAuditLog("Safe audit check complete. Policy is green.");
        await fetchData(true);
      }
    } catch (e) {
      addAuditLog("Audit run failure.");
    } finally {
      setScanLoading(false);
    }
  };

  // Run Simulation check (Attacks)
  const handleSimulationScan = async () => {
    setScanLoading(true);
    addAuditLog("WARNING: Running endpoint attack vector simulation...");
    try {
      const res = await fetch(`http://localhost:8000/api/device/${deviceId}/simulate-scan?scan_type=simulation`, {
        method: "POST"
      });
      if (res.ok) {
        addAuditLog("CRITICAL: Attack simulation logs successfully injected!");
        addAuditLog("Alert generated: Suspicious command execution (PowerShell iex)");
        addAuditLog("Alert generated: Credential Dumping (Mimikatz execution)");
        addAuditLog("Alert generated: Outbound socket created from shell process");
        addAuditLog("Alert generated: Registry boot persistence autostart configuration");
        await fetchData(true);
      }
    } catch (e) {
      addAuditLog("Scan run failure.");
    } finally {
      setScanLoading(false);
    }
  };

  // Resolve an alert
  const handleResolveAlert = async (alertId: number) => {
    try {
      const res = await fetch(`http://localhost:8000/api/alert/${alertId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "RESOLVED" })
      });
      if (res.ok) {
        addAuditLog(`Mitigated Alert #${alertId}. Recalculating host risk score.`);
        await fetchData(true);
      }
    } catch (e) {
      addAuditLog("Alert resolution failed.");
    }
  };

  // Run AI investigation
  const handleAiInvestigate = async () => {
    setAiLoading(true);
    addAuditLog("Querying Copilot AI Analysis pipeline... parsing threat tree");
    try {
      const res = await fetch(`http://localhost:8000/api/device/${deviceId}/ai-investigate`, {
        method: "POST"
      });
      if (res.ok) {
        const data = await res.json();
        setInvestigation(data);
        addAuditLog("AI Copilot Investigation Report generated.");
        setActiveTab("ai");
      }
    } catch (e) {
      addAuditLog("AI Copilot request error.");
    } finally {
      setAiLoading(false);
    }
  };

  // Export report
  const handleExportReport = async () => {
    addAuditLog("Assembling assessment report markdown file...");
    try {
      const res = await fetch(`http://localhost:8000/api/device/${deviceId}/report`);
      if (res.ok) {
        const data = await res.json();
        const blob = new Blob([data.report_markdown], { type: "text/markdown" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `PESZARA_XDR_${device?.hostname || "Device"}_Report.md`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        addAuditLog("Assessment report exported successfully.");
      }
    } catch (e) {
      addAuditLog("Report compilation error.");
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#080a0f] text-[#f3f4f6] font-mono flex flex-col items-center justify-center space-y-4">
        <RotateCcw className="h-8 w-8 text-emerald-400 animate-spin" />
        <span className="text-xs">Connecting agent session...</span>
      </div>
    );
  }

  if (!device) {
    return (
      <div className="min-h-screen bg-[#080a0f] text-[#f3f4f6] font-mono flex flex-col items-center justify-center space-y-4">
        <ShieldAlert className="h-10 w-10 text-red-500" />
        <span className="text-xs">Device not registered on server.</span>
        <Link href="/" className="px-3 py-1.5 bg-[#0f131a] border border-[#1d2433] rounded text-xs">
          Return to Hub
        </Link>
      </div>
    );
  }

  // Count alerts
  const totalAlerts = alerts.length;
  const unresolvedAlerts = alerts.filter((a) => a.status === "UNRESOLVED");
  const warnings = unresolvedAlerts.filter((a) => a.severity.toUpperCase() === "MEDIUM").length;
  const criticals = unresolvedAlerts.filter((a) => a.severity.toUpperCase() === "CRITICAL" || a.severity.toUpperCase() === "HIGH").length;

  const getThreatAssessmentText = (score: number) => {
    if (score >= 70) return "IMMEDIATE RESPONSE REQUIRED";
    if (score >= 35) return "POTENTIAL BREACH DETECTED";
    if (score > 0) return "LOW ALERT RUNNING";
    return "NO THREATS FOUND";
  };

  const getAssessmentBarColor = (score: number) => {
    if (score >= 70) return "bg-red-500 shadow-[0_0_15px_rgba(239,68,68,0.7)]";
    if (score >= 35) return "bg-yellow-500 shadow-[0_0_15px_rgba(234,179,8,0.7)]";
    return "bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.7)]";
  };

  // Filter lists based on search
  const filteredProcesses = processes.filter(
    (p) =>
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.pid.toString().includes(searchQuery) ||
      (p.username && p.username.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const filteredConnections = connections.filter(
    (c) =>
      (c.process_name && c.process_name.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (c.raddr && c.raddr.includes(searchQuery)) ||
      (c.pid && c.pid.toString().includes(searchQuery))
  );

  const filteredAlerts = alerts.filter(
    (a) =>
      a.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.severity.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <main className="min-h-screen bg-[#080a0f] text-[#f3f4f6] font-mono select-none">
      {/* Top Header */}
      <header className="border-b border-[#1d2433] bg-[#0c0f16]/90 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-3 sm:px-6 lg:px-8 flex justify-between items-center">
          <div className="flex items-center space-x-4">
            <Link
              href="/"
              className="p-1.5 rounded bg-[#0f131a] hover:bg-[#1d2433] border border-[#1d2433] text-[#9ca3af] hover:text-white transition-colors"
            >
              <ArrowLeft className="h-4 w-4" />
            </Link>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-md font-bold text-white uppercase flex items-center space-x-1.5">
                  <Server className="h-4 w-4 text-[#9ca3af]" />
                  <span>{device.hostname}</span>
                </h1>
                <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-ping"></span>
              </div>
              <p className="text-[10px] text-[#9ca3af]">ID: {device.id}</p>
            </div>
          </div>

          <div className="flex items-center space-x-3 text-xs">
            <div className="hidden md:flex space-x-4 mr-4 text-[11px] text-[#9ca3af]">
              <div>
                <span className="text-gray-600 block">OS PLATFORM:</span>
                <span className="text-white uppercase font-bold">{device.os_name}</span>
              </div>
              <div>
                <span className="text-gray-600 block">IP ADDRESS:</span>
                <span className="text-white font-bold">{device.ip_address}</span>
              </div>
              <div>
                <span className="text-gray-600 block">ACTIVE USER:</span>
                <span className="text-white font-bold truncate max-w-[100px] block">{device.logged_in_user || "SYSTEM"}</span>
              </div>
            </div>
            
            <button
              onClick={handleExportReport}
              className="px-3 py-1.5 bg-emerald-950/40 hover:bg-emerald-900 border border-emerald-800 text-emerald-400 hover:text-emerald-300 font-bold rounded transition-colors flex items-center space-x-1"
            >
              <FileText className="h-3.5 w-3.5" />
              <span>EXPORT REPORT</span>
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8 space-y-6">
        
        {/* Metric Cards Banner */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="p-4 border border-[#1d2433] bg-[#0f131a] rounded-lg">
            <span className="text-[10px] text-gray-600 block uppercase">TOTAL ALERTS</span>
            <span className="text-xl font-bold text-white block mt-1">{totalAlerts}</span>
            <span className="text-[9px] text-[#9ca3af] block mt-0.5">IN AGENT SESSION</span>
          </div>

          <div className="p-4 border border-[#1d2433] bg-[#0f131a] rounded-lg">
            <span className="text-[10px] text-gray-600 block uppercase">CRITICAL / HIGH</span>
            <span className="text-xl font-bold text-red-500 block mt-1">{criticals}</span>
            <span className="text-[9px] text-[#9ca3af] block mt-0.5">UNRESOLVED DETECTS</span>
          </div>

          <div className="p-4 border border-[#1d2433] bg-[#0f131a] rounded-lg">
            <span className="text-[10px] text-gray-600 block uppercase">WARNINGS</span>
            <span className="text-xl font-bold text-yellow-500 block mt-1">{warnings}</span>
            <span className="text-[9px] text-[#9ca3af] block mt-0.5">SUSPICIOUS ACTIONS</span>
          </div>

          <div className="p-4 border border-[#1d2433] bg-[#0f131a] rounded-lg">
            <span className="text-[10px] text-gray-600 block uppercase">CPU / MEMORY</span>
            <div className="flex items-center space-x-3 mt-1.5">
              <span className="text-sm font-bold text-white flex items-center space-x-1">
                <Cpu className="h-3.5 w-3.5 text-gray-600" />
                <span>{device.cpu_usage.toFixed(0)}%</span>
              </span>
              <span className="text-sm font-bold text-white flex items-center space-x-1">
                <Activity className="h-3.5 w-3.5 text-gray-600" />
                <span>{device.memory_usage.toFixed(0)}%</span>
              </span>
            </div>
          </div>

          <div className="p-4 border border-[#1d2433] bg-[#0f131a] rounded-lg col-span-2 md:col-span-1">
            <span className="text-[10px] text-gray-600 block uppercase">OVERALL RISK</span>
            <span className={`text-xl font-bold block mt-1 ${device.risk_score >= 70 ? 'text-red-500 glow-red' : device.risk_score >= 35 ? 'text-yellow-500 glow-yellow' : 'text-emerald-500 glow-green'}`}>
              {device.risk_score.toFixed(0)}%
            </span>
            <span className="text-[9px] text-[#9ca3af] block mt-0.5">CRITICAL INDEX</span>
          </div>
        </div>

        {/* Threat Assessment Slider & Actions */}
        <div className="p-6 border border-[#1d2433] bg-[#0f131a] rounded-lg space-y-4 relative overflow-hidden">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center space-y-4 md:space-y-0">
            <div>
              <span className="text-[10px] text-gray-600 uppercase tracking-wider block">THREAT ASSESSMENT LEVEL</span>
              <h2 className={`text-lg font-bold mt-1 ${device.risk_score >= 70 ? 'text-red-500 glow-red' : device.risk_score >= 35 ? 'text-yellow-500 glow-yellow' : 'text-emerald-500 glow-green'}`}>
                {getThreatAssessmentText(device.risk_score)}
              </h2>
            </div>
            
            {/* Simulation controls */}
            <div className="flex items-center space-x-3">
              <button
                disabled={scanLoading}
                onClick={handleSafeCheck}
                className="px-3 py-1.5 bg-[#141b25] border border-[#20293a] hover:border-emerald-500 text-[#9ca3af] hover:text-white rounded transition-all flex items-center space-x-1.5 text-xs font-semibold"
              >
                <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
                <span>RUN SAFE CHECK</span>
              </button>
              
              <button
                disabled={scanLoading}
                onClick={handleSimulationScan}
                className="px-3 py-1.5 bg-red-950/20 border border-red-900/50 hover:border-red-500 text-red-400 hover:text-red-300 rounded transition-all flex items-center space-x-1.5 text-xs font-semibold"
              >
                <Play className="h-3.5 w-3.5 text-red-500" />
                <span>RUN SIMULATION SCAN</span>
              </button>
            </div>
          </div>

          {/* Assessment bar slider representation */}
          <div className="space-y-2">
            <div className="w-full h-3 bg-gray-950 rounded border border-[#1d2433] overflow-hidden relative">
              <div
                className={`h-full ${getAssessmentBarColor(device.risk_score)} transition-all duration-500`}
                style={{ width: `${device.risk_score || 1}%` }}
              ></div>
              {/* Threshold lines */}
              <div className="absolute top-0 bottom-0 left-[35%] w-[1px] bg-[#1d2433]"></div>
              <div className="absolute top-0 bottom-0 left-[70%] w-[1px] bg-[#1d2433]"></div>
            </div>
            <div className="flex justify-between text-[10px] text-gray-600 px-0.5">
              <span>CLEAN (0-35)</span>
              <span>WARNING (35-70)</span>
              <span>CRITICAL (70-100)</span>
            </div>
          </div>
        </div>

        {/* Console scrolling logs */}
        <div className="border border-[#1d2433] bg-[#0c0f16] rounded-lg overflow-hidden">
          <div className="px-4 py-2 border-b border-[#1d2433] bg-[#0f131a] flex justify-between items-center">
            <span className="text-xs text-[#9ca3af] flex items-center space-x-1.5 font-bold">
              <Terminal className="h-3.5 w-3.5 text-emerald-400" />
              <span>REAL-TIME AUDIT LOG FEED</span>
            </span>
            <span className="h-2 w-2 bg-emerald-500 rounded-full animate-pulse"></span>
          </div>
          <div className="p-4 h-32 overflow-y-auto text-[11px] font-mono text-[#9ca3af] space-y-1">
            {auditLogs.map((log, index) => (
              <div key={index} className="flex space-x-2 leading-relaxed">
                <span className="text-[#10b981]">&gt;</span>
                <span className="break-all">{log}</span>
              </div>
            ))}
            <div ref={consoleEndRef} />
          </div>
        </div>

        {/* Dashboard Tabs & search */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Detailed Data Tabs Section */}
          <div className="lg:col-span-2 space-y-4">
            
            {/* Tabs List */}
            <div className="flex border-b border-[#1d2433] space-x-2 overflow-x-auto">
              {[
                { id: "alerts", label: "Alerts", icon: ShieldAlert, count: unresolvedAlerts.length },
                { id: "processes", label: "Processes", icon: Activity, count: processes.length },
                { id: "sockets", label: "Sockets", icon: Network, count: connections.length },
                { id: "files", label: "File Logs", icon: FolderOpen, count: fileEvents.length }
              ].map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => {
                      setActiveTab(tab.id as any);
                      setSearchQuery("");
                    }}
                    className={`px-4 py-2 text-xs font-semibold border-b-2 flex items-center space-x-2 transition-all ${
                      activeTab === tab.id
                        ? "border-emerald-500 text-white bg-[#0f131a]/55"
                        : "border-transparent text-[#9ca3af] hover:text-white"
                    }`}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    <span>{tab.label}</span>
                    {tab.count > 0 && (
                      <span className={`px-1.5 py-0.2 rounded text-[10px] ${
                        tab.id === "alerts" ? "bg-red-950 text-red-400 border border-red-900" : "bg-gray-900 text-[#9ca3af]"
                      }`}>
                        {tab.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Search filter input */}
            <div className="relative">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-gray-600" />
              <input
                type="text"
                placeholder={`Search ${activeTab}...`}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-[#0c0f16] border border-[#1d2433] rounded focus:border-emerald-500 outline-none text-xs text-white"
              />
            </div>

            {/* Tab Contents */}
            <div className="border border-[#1d2433] bg-[#0f131a] rounded-lg p-4 overflow-hidden min-h-[300px]">
              
              {/* ALERTS TAB */}
              {activeTab === "alerts" && (
                <div className="space-y-4">
                  {filteredAlerts.length === 0 ? (
                    <div className="text-center py-12 text-xs text-[#9ca3af]">
                      No alerts match filter or are logged.
                    </div>
                  ) : (
                    filteredAlerts.map((alert) => {
                      const getSeverityColor = (sev: string) => {
                        const s = sev.toUpperCase();
                        if (s === "CRITICAL") return "text-red-500 border-red-500/20 bg-red-950/20";
                        if (s === "HIGH") return "text-orange-500 border-orange-500/20 bg-orange-950/20";
                        if (s === "MEDIUM") return "text-yellow-500 border-yellow-500/20 bg-yellow-950/20";
                        return "text-blue-400 border-blue-900/30 bg-blue-950/10";
                      };

                      return (
                        <div
                          key={alert.id}
                          className={`p-4 border rounded-lg transition-all ${
                            alert.status === "RESOLVED" ? "opacity-40 border-[#1d2433]" : "border-[#1d2433]"
                          }`}
                        >
                          <div className="flex justify-between items-start">
                            <div className="space-y-1">
                              <div className="flex items-center space-x-2">
                                <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase border ${getSeverityColor(alert.severity)}`}>
                                  {alert.severity}
                                </span>
                                <h4 className="font-bold text-white text-xs">{alert.title}</h4>
                              </div>
                              <p className="text-[11px] text-[#9ca3af] leading-relaxed mt-1.5">{alert.description}</p>
                              
                              {/* Mitre Att&ck Tags */}
                              {(alert.mitre_tactic || alert.mitre_technique) && (
                                <div className="flex space-x-2 mt-2">
                                  {alert.mitre_tactic && (
                                    <span className="px-2 py-0.5 bg-red-950/40 text-[9px] text-red-400 border border-red-900/40 rounded uppercase">
                                      MITRE: {alert.mitre_tactic}
                                    </span>
                                  )}
                                  {alert.mitre_technique && (
                                    <span className="px-2 py-0.5 bg-gray-950 text-[9px] text-emerald-400 border border-emerald-900/40 rounded font-semibold">
                                      {alert.mitre_technique}
                                    </span>
                                  )}
                                </div>
                              )}
                            </div>

                            {alert.status === "UNRESOLVED" ? (
                              <button
                                onClick={() => handleResolveAlert(alert.id)}
                                className="px-2 py-1 bg-emerald-950 border border-emerald-800 text-emerald-400 hover:text-white rounded text-[10px] transition-colors"
                              >
                                RESOLVE
                              </button>
                            ) : (
                              <span className="text-[10px] text-emerald-500 border border-emerald-950/40 px-2 py-1 rounded">
                                RESOLVED
                              </span>
                            )}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              )}

              {/* PROCESSES TAB */}
              {activeTab === "processes" && (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-[#1d2433] text-gray-600 uppercase text-[10px]">
                        <th className="py-2">PID</th>
                        <th className="py-2">PPID</th>
                        <th className="py-2">Process Name</th>
                        <th className="py-2">Active User</th>
                        <th className="py-2 hidden md:table-cell">SHA256 Hash</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1d2433] text-[11px]">
                      {filteredProcesses.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="py-8 text-center text-[#9ca3af]">
                            No processes mapped.
                          </td>
                        </tr>
                      ) : (
                        filteredProcesses.map((proc) => {
                          const isMalicious = proc.name.toLowerCase() === "mimikatz.exe" || proc.name.toLowerCase() === "nc.exe";
                          return (
                            <tr key={proc.id} className={isMalicious ? "bg-red-950/20 text-red-400" : "hover:bg-gray-950/30"}>
                              <td className="py-2.5 font-bold">{proc.pid}</td>
                              <td className="py-2.5 text-gray-600">{proc.ppid || "N/A"}</td>
                              <td className="py-2.5 font-semibold text-white max-w-[150px] truncate" title={proc.cmdline}>
                                {proc.name}
                              </td>
                              <td className="py-2.5 text-[#9ca3af]">{proc.username || "N/A"}</td>
                              <td className="py-2.5 hidden md:table-cell font-mono text-[10px] text-[#9ca3af]">
                                {proc.sha256 ? `${proc.sha256.substring(0, 15)}...` : "N/A"}
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              {/* SOCKETS TAB */}
              {activeTab === "sockets" && (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-[#1d2433] text-gray-600 uppercase text-[10px]">
                        <th className="py-2">PID</th>
                        <th className="py-2">Process</th>
                        <th className="py-2">Local Address</th>
                        <th className="py-2">Remote Connection</th>
                        <th className="py-2">Reputation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1d2433] text-[11px]">
                      {filteredConnections.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="py-8 text-center text-[#9ca3af]">
                            No established connections.
                          </td>
                        </tr>
                      ) : (
                        filteredConnections.map((conn) => {
                          const isC2 = conn.raddr?.startsWith("91.241.12.33");
                          return (
                            <tr key={conn.id} className={isC2 ? "bg-red-950/20 text-red-400" : "hover:bg-gray-950/30"}>
                              <td className="py-2.5 font-bold">{conn.pid || "N/A"}</td>
                              <td className="py-2.5 text-white font-semibold">{conn.process_name || "unknown"}</td>
                              <td className="py-2.5 text-[#9ca3af]">{conn.laddr || "N/A"}</td>
                              <td className="py-2.5 font-bold text-white flex items-center space-x-1.5">
                                <span>{conn.raddr || "N/A"}</span>
                                {isC2 && <ExternalLink className="h-3 w-3 text-red-500" />}
                              </td>
                              <td className="py-2.5">
                                {isC2 ? (
                                  <span className="text-[10px] text-red-500 font-bold border border-red-500/20 px-1.5 py-0.5 rounded">
                                    C2 Server (85%)
                                  </span>
                                ) : (
                                  <span className="text-[10px] text-emerald-500 border border-emerald-950/40 px-1.5 py-0.5 rounded">
                                    Trusted IP
                                  </span>
                                )}
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              {/* FILES TAB */}
              {activeTab === "files" && (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-[#1d2433] text-gray-600 uppercase text-[10px]">
                        <th className="py-2">Action</th>
                        <th className="py-2">Filepath</th>
                        <th className="py-2">Time</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1d2433] text-[11px]">
                      {fileEvents.length === 0 ? (
                        <tr>
                          <td colSpan={3} className="py-8 text-center text-[#9ca3af]">
                            No recent file activity logs.
                          </td>
                        </tr>
                      ) : (
                        fileEvents.map((fe) => {
                          const isLocked = fe.filepath.endsWith(".locked") || fe.filepath.endsWith(".crypto");
                          return (
                            <tr key={fe.id} className={isLocked ? "bg-red-950/20 text-red-400 font-bold" : "hover:bg-gray-950/30"}>
                              <td className="py-2.5">
                                <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                                  fe.action === "CREATED" ? "bg-emerald-950 text-emerald-400 border border-emerald-900" :
                                  fe.action === "DELETED" ? "bg-red-950 text-red-400 border border-red-900" : "bg-yellow-950 text-yellow-400 border border-yellow-900"
                                }`}>
                                  {fe.action}
                                </span>
                              </td>
                              <td className="py-2.5 text-white max-w-[250px] truncate" title={fe.filepath}>
                                {fe.filepath}
                              </td>
                              <td className="py-2.5 text-gray-600">
                                {new Date(fe.timestamp).toLocaleTimeString()}
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* AI Investigation Copilot Sidebar */}
          <div className="space-y-6">
            
            <div className="p-6 border border-[#1d2433] bg-[#0f131a] rounded-lg relative overflow-hidden flex flex-col justify-between min-h-[400px]">
              <div className="absolute top-0 right-0 h-32 w-32 bg-emerald-500/5 blur-[50px] rounded-full pointer-events-none"></div>
              
              <div>
                <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4 flex items-center space-x-2">
                  <Bot className="h-4.5 w-4.5 text-emerald-400" />
                  <span>AI Investigation Copilot</span>
                </h3>

                {aiLoading ? (
                  <div className="py-12 flex flex-col items-center justify-center space-y-3">
                    <Bot className="h-8 w-8 text-emerald-400 animate-bounce" />
                    <span className="text-xs text-[#9ca3af]">Analyzing host alert chain...</span>
                  </div>
                ) : investigation ? (
                  <div className="space-y-4 text-xs">
                    {/* Summary */}
                    <div>
                      <span className="text-gray-600 block uppercase font-bold mb-1">Incident Summary</span>
                      <p className="text-[#f3f4f6] bg-gray-950/40 p-2.5 rounded border border-[#1d2433] leading-relaxed">
                        {investigation.summary}
                      </p>
                    </div>

                    {/* Analysis */}
                    <div>
                      <span className="text-gray-600 block uppercase font-bold mb-1">Triage & Analysis</span>
                      <div className="text-[#9ca3af] leading-relaxed space-y-2 whitespace-pre-line p-2.5 bg-gray-950/40 border border-[#1d2433] rounded overflow-y-auto max-h-[160px]">
                        {investigation.analysis}
                      </div>
                    </div>

                    {/* Remediation */}
                    <div>
                      <span className="text-gray-600 block uppercase font-bold mb-1">Suggested Next Steps</span>
                      <div className="text-emerald-400 whitespace-pre-line bg-emerald-950/20 p-2.5 rounded border border-emerald-900/50 leading-relaxed font-semibold">
                        {investigation.remediation}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-12 space-y-4">
                    <ShieldAlert className="h-8 w-8 text-yellow-500 mx-auto" />
                    <p className="text-xs text-[#9ca3af]">
                      Threat vector established on host. Click analyze below to trigger the AI incident assessment pipeline.
                    </p>
                  </div>
                )}
              </div>

              {!aiLoading && (
                <button
                  onClick={handleAiInvestigate}
                  className="w-full mt-6 py-2.5 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800 text-emerald-400 hover:text-emerald-300 text-xs font-bold text-center rounded transition-all flex items-center justify-center space-x-1.5"
                >
                  <Bot className="h-4 w-4" />
                  <span>{investigation ? "RE-ANALYZE INCIDENT" : "QUERY AI COPILOT"}</span>
                </button>
              )}
            </div>
            
          </div>
        </div>
      </div>
    </main>
  );
}
