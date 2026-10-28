import type { Metadata } from "next";
import "./globals.css";
import { Navbar } from "@/components/Navbar";
import { Footer } from "@/components/Footer";

export const metadata: Metadata = {
  title: "AIThreatLab | Detection Engineering Platform",
  description:
    "From security research to operational detection across AI security, architectural coverage, and intelligent security workflows.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen">
        <Navbar />
        <main className="atl-page">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
