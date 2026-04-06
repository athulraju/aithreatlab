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
        {/* Minimal icon: hexagonal node with circuit lines */}
        <svg
          width="22"
          height="22"
          viewBox="0 0 22 22"
          fill="none"
          aria-hidden="true"
          className="flex-shrink-0"
        >
          {/* Outer hexagon outline */}
          <path
            d="M11 1.5L19.5 6.25V15.75L11 20.5L2.5 15.75V6.25L11 1.5Z"
            stroke="rgb(34 211 238 / 0.5)"
            strokeWidth="1"
            strokeLinejoin="round"
          />
          {/* Center node */}
          <circle cx="11" cy="11" r="2" fill="rgb(34 211 238)" />
          {/* Neural connection lines */}
          <line x1="11" y1="9" x2="11" y2="5.5" stroke="rgb(34 211 238 / 0.45)" strokeWidth="0.9" strokeLinecap="round" />
          <line x1="11" y1="13" x2="11" y2="16.5" stroke="rgb(34 211 238 / 0.45)" strokeWidth="0.9" strokeLinecap="round" />
          <line x1="9.27" y1="10" x2="6.2" y2="8.25" stroke="rgb(34 211 238 / 0.45)" strokeWidth="0.9" strokeLinecap="round" />
          <line x1="12.73" y1="12" x2="15.8" y2="13.75" stroke="rgb(34 211 238 / 0.45)" strokeWidth="0.9" strokeLinecap="round" />
          <line x1="9.27" y1="12" x2="6.2" y2="13.75" stroke="rgb(34 211 238 / 0.45)" strokeWidth="0.9" strokeLinecap="round" />
          <line x1="12.73" y1="10" x2="15.8" y2="8.25" stroke="rgb(34 211 238 / 0.45)" strokeWidth="0.9" strokeLinecap="round" />
          {/* Outer nodes */}
          <circle cx="11" cy="4.5" r="1" fill="rgb(34 211 238 / 0.5)" />
          <circle cx="11" cy="17.5" r="1" fill="rgb(34 211 238 / 0.5)" />
          <circle cx="5.5" cy="7.75" r="1" fill="rgb(34 211 238 / 0.5)" />
          <circle cx="16.5" cy="14.25" r="1" fill="rgb(34 211 238 / 0.5)" />
          <circle cx="5.5" cy="14.25" r="1" fill="rgb(34 211 238 / 0.5)" />
          <circle cx="16.5" cy="7.75" r="1" fill="rgb(34 211 238 / 0.5)" />
        </svg>

        {/* Wordmark */}
        <span className="font-semibold text-sm tracking-tight leading-none">
          <span className="text-cyan-400">AI</span>
          <span className="text-white">Detect</span>
          <span className="text-gray-500">Lab</span>
        </span>
      </div>
    </Link>
  );
}
