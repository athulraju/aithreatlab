"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { Menu, X, ArrowUpRight } from "lucide-react";
import { useState } from "react";
import { Logo } from "@/components/Logo";

const allLinks = [
  { href: "/detections",              label: "Detections" },
  { href: "/coverage",                label: "Coverage" },
  { href: "/ai-security",             label: "AI Security" },
  { href: "/agent-skills",            label: "Agents" },
  { href: "/playground",              label: "Playground" },
  { href: "/converter",               label: "Converter" },
  { href: "/research",                label: "Research" },
];

export function Navbar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-[#bce2d2]/[0.09] bg-[#05110f]/80 backdrop-blur-2xl">
      <div className="atl-shell">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Logo />

          {/* Desktop Nav */}
          <nav className="hidden lg:flex items-center gap-0.5" aria-label="Primary navigation">
            {allLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className={cn(
                  "px-3 py-2 text-[11px] font-medium tracking-wide transition-all",
                  pathname === link.href || pathname.startsWith(link.href + "/")
                    ? "text-[#ece8df]"
                    : "text-[#77736d] hover:text-[#ece8df]"
                )}
              >
                {link.label}
              </Link>
            ))}
          </nav>

          <div className="hidden items-center gap-2 lg:flex">
            <Link href="/labs" className="inline-flex items-center gap-1.5 border-l border-[#bce2d2]/10 px-4 py-2 text-[11px] font-medium text-[#8da59b] transition-all hover:text-[#dce8e1]">
              Labs <ArrowUpRight className="h-3.5 w-3.5 text-[#83d7b6]" />
            </Link>
          </div>

          {/* Mobile menu toggle */}
          <button
            className="rounded-lg border border-[#bce2d2]/10 p-2 text-[#8da59b] hover:text-white lg:hidden"
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label={mobileOpen ? "Close menu" : "Open menu"}
          >
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile nav */}
      {mobileOpen && (
        <div className="border-t border-[#bce2d2]/[0.08] bg-[#061411] px-4 py-4 shadow-2xl lg:hidden">
          {[...allLinks, { href: "/labs", label: "Labs" }, { href: "/about", label: "About" }].map((link) => (
            <Link
              key={link.href}
              href={link.href}
              onClick={() => setMobileOpen(false)}
              className={cn(
                "block px-3 py-2.5 rounded-md text-sm font-medium mb-1 transition-all",
                pathname === link.href
                      ? "bg-[#83d7b6]/10 text-[#a6f1d1]"
                      : "text-[#8da59b] hover:text-white"
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
