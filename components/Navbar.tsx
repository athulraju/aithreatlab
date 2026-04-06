"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { Shield, Menu, X } from "lucide-react";
import { useState } from "react";

const navLinks = [
  { href: "/converter", label: "Converter" },
  { href: "/detections", label: "Detections" },
  { href: "/coverage", label: "Coverage" },
  { href: "/ai-security", label: "AI Security" },
  { href: "/playground", label: "Playground" },
  { href: "/research", label: "Research" },
  { href: "/about", label: "About" },
];

export function Navbar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  return (
    <header className="fixed top-0 left-0 right-0 z-50 border-b border-white/[0.06] bg-[#080810]/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2.5 group">
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center group-hover:shadow-lg group-hover:shadow-cyan-500/25 transition-all">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <span className="font-semibold text-white text-sm tracking-tight">
              Detect<span className="text-cyan-400">Lab</span>
            </span>
          </Link>

          {/* Desktop Nav */}
          <nav className="hidden md:flex items-center gap-1">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm font-medium transition-all",
                  pathname === link.href || pathname.startsWith(link.href + "/")
                    ? "text-white bg-white/10"
                    : "text-gray-400 hover:text-white hover:bg-white/5"
                )}
              >
                {link.label}
              </Link>
            ))}
          </nav>

          {/* CTA */}
          <div className="hidden md:flex items-center gap-3">
            <Link
              href="/converter"
              className="px-3 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-white text-sm font-medium transition-all shadow-lg shadow-cyan-500/20"
            >
              Try Converter
            </Link>
          </div>

          {/* Mobile menu toggle */}
          <button
            className="md:hidden text-gray-400 hover:text-white"
            onClick={() => setOpen(!open)}
          >
            {open ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile nav */}
      {open && (
        <div className="md:hidden border-t border-white/[0.06] bg-[#080810] px-4 py-4">
          {navLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              onClick={() => setOpen(false)}
              className={cn(
                "block px-3 py-2.5 rounded-md text-sm font-medium mb-1 transition-all",
                pathname === link.href
                  ? "text-white bg-white/10"
                  : "text-gray-400 hover:text-white"
              )}
            >
              {link.label}
            </Link>
          ))}
        </div>
      )}
    </header>
  );
}
