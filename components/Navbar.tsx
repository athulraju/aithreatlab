"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { Menu, X, ChevronDown } from "lucide-react";
import { useState, useRef, useEffect } from "react";
import { Logo } from "@/components/Logo";

// Primary nav — always visible on desktop
const primaryLinks = [
  { href: "/detections",   label: "Detections" },
  { href: "/coverage",     label: "Coverage" },
  { href: "/ai-security",  label: "AI Security" },
  { href: "/agent-skills", label: "Agent Skills" },
  { href: "/playground",   label: "Playground" },
];

// Secondary nav — in "More" dropdown on desktop, flat in mobile menu
const secondaryLinks = [
  { href: "/converter", label: "Converter" },
  { href: "/research",  label: "Research" },
  { href: "/about",     label: "About" },
];

const allLinks = [...primaryLinks, ...secondaryLinks];

export function Navbar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen]   = useState(false);
  const [moreOpen,   setMoreOpen]     = useState(false);
  const moreRef = useRef<HTMLDivElement>(null);

  // Close "More" dropdown on outside click
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (moreRef.current && !moreRef.current.contains(e.target as Node)) {
        setMoreOpen(false);
      }
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const isSecondaryActive = secondaryLinks.some(
    (l) => pathname === l.href || pathname.startsWith(l.href + "/")
  );

  return (
    <header className="fixed top-0 left-0 right-0 z-50 border-b border-white/[0.06] bg-[#080810]/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          {/* Logo */}
          <Logo />

          {/* Desktop Nav */}
          <nav className="hidden md:flex items-center gap-1">
            {primaryLinks.map((link) => (
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

            {/* More dropdown */}
            <div ref={moreRef} className="relative">
              <button
                onClick={() => setMoreOpen((o) => !o)}
                className={cn(
                  "flex items-center gap-1 px-3 py-1.5 rounded-md text-sm font-medium transition-all",
                  isSecondaryActive || moreOpen
                    ? "text-white bg-white/10"
                    : "text-gray-400 hover:text-white hover:bg-white/5"
                )}
              >
                More
                <ChevronDown className={cn("w-3.5 h-3.5 transition-transform duration-150", moreOpen && "rotate-180")} />
              </button>
              {moreOpen && (
                <div className="absolute top-full right-0 mt-1 w-40 rounded-lg border border-white/10 bg-[#0c0c18] shadow-xl py-1 z-50">
                  {secondaryLinks.map((link) => (
                    <Link
                      key={link.href}
                      href={link.href}
                      onClick={() => setMoreOpen(false)}
                      className={cn(
                        "block px-4 py-2 text-sm transition-colors duration-150",
                        pathname === link.href
                          ? "text-white bg-white/10"
                          : "text-gray-400 hover:text-white hover:bg-white/5"
                      )}
                    >
                      {link.label}
                    </Link>
                  ))}
                </div>
              )}
            </div>
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
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label={mobileOpen ? "Close menu" : "Open menu"}
          >
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile nav — all links flat */}
      {mobileOpen && (
        <div className="md:hidden border-t border-white/[0.06] bg-[#080810] px-4 py-4">
          {allLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              onClick={() => setMobileOpen(false)}
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
