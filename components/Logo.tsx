"use client";

import Link from "next/link";

interface LogoProps {
  className?: string;
  linkClassName?: string;
}

export function Logo({ className, linkClassName }: LogoProps) {
  return (
    <Link href="/" className={`flex items-center gap-2 group ${linkClassName ?? ""}`}>
      <div className={`flex items-center gap-2 ${className ?? ""}`}>
        {/* Radar lock: a dish, one sweep, and the point it's found. */}
        <svg
          width="22"
          height="22"
          viewBox="0 0 22 22"
          fill="none"
          aria-hidden="true"
          className="flex-shrink-0"
        >
          <circle cx="11" cy="11" r="8.5" stroke="#83d7b6" strokeWidth="1.1" strokeOpacity=".9"/>
          <circle cx="11" cy="11" r="5" stroke="#d08a5d" strokeWidth="1" strokeOpacity=".75"/>
          <g
            className="origin-[11px_11px] transition-none group-hover:animate-[spin_2.4s_linear_infinite] motion-reduce:group-hover:animate-none"
          >
            <line x1="11" y1="11" x2="11" y2="2.5" stroke="#83d7b6" strokeWidth="1.3" strokeLinecap="round"/>
            <circle cx="11" cy="2.5" r="1.1" fill="#d08a5d"/>
          </g>
          <circle cx="11" cy="11" r="1.8" fill="#a6f1d1"/>
        </svg>

        {/* Wordmark */}
        <span className="font-semibold text-sm tracking-tight leading-none">
          <span className="text-[#a6f1d1]">AI</span>
          <span className="text-white">Threat</span>
          <span className="text-[#718a80]">Lab</span>
        </span>
      </div>
    </Link>
  );
}
