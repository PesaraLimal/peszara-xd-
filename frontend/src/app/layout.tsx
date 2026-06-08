import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PESZARA XDR - AI Endpoint Protection Platform",
  description: "AI-Powered Endpoint Security, Threat Detection & Investigation Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased bg-[#080a0f] text-[#f3f4f6]">
        {children}
      </body>
    </html>
  );
}
