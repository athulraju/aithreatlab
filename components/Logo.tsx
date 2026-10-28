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
        {/* Three converging traces: research, logic, and coverage. */}
        <svg
          width="22"
          height="22"
          viewBox="0 0 22 22"
          fill="none"
          aria-hidden="true"
          className="flex-shrink-0"
        >
          <path d="M2 5.5C7 5.5 7.5 11 12 11S16 7 20 7" stroke="#83d7b6" strokeWidth="1.25" strokeLinecap="round"/>
          <path d="M2 11C6.5 11 8 11 12 11s4 4 8 4" stroke="#d08a5d" strokeOpacity=".82" strokeWidth="1" strokeLinecap="round"/>
          <path d="M2 16.5C7 16.5 7.5 11 12 11s4-1 8-1" stroke="#83d7b6" strokeOpacity=".4" strokeWidth="1" strokeLinecap="round"/>
          <circle cx="12" cy="11" r="2.15" fill="#a6f1d1"/>
          <circle cx="20" cy="7" r="1" fill="#d08a5d"/>
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
