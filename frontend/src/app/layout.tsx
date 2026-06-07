import './globals.css'
import { Inter } from 'next/font/google'

const inter = Inter({ subsets: ['latin'] })

export const metadata = {
  title: 'PESZARA XDR - Command Center',
  description: 'AI-Powered Endpoint Security, Threat Detection & Investigation Platform',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <div className="min-h-screen bg-cyber-bg flex flex-col">
          {/* Global Cyber Header Bar */}
          <header className="border-b border-cyber-border bg-[#0E131F] px-6 py-4 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-3 h-3 bg-cyber-accent rounded-full animate-ping"></div>
              <span className="font-mono text-xl font-bold tracking-wider text-cyber-text">
                PESZARA <span className="text-cyber-accent">XDR</span>
              </span>
              <span className="text-xs bg-[#1A2536] px-2.5 py-1 rounded-md text-cyber-muted uppercase border border-cyber-border font-semibold tracking-wider">
                MVP CONSOLE
              </span>
            </div>
            <div className="flex items-center space-x-6">
              <div className="text-sm font-mono text-cyber-muted">
                STATUS: <span className="text-cyber-green font-bold">SECURE OPERATIONAL</span>
              </div>
            </div>
          </header>
          
          <main className="flex-1 flex flex-col">
            {children}
          </main>
        </div>
      </body>
    </html>
  )
}
