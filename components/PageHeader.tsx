"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

type Accent = "cyan" | "blue" | "purple" | "orange" | "yellow" | "green" | "gray";

interface PageHeaderProps {
  eyebrow?: string;
  title: string;
  description?: string;
  children?: React.ReactNode;
  className?: string;
  accent?: Accent;
}

const accentStyles: Record<Accent, { eyebrow: string; rule: string }> = {
  cyan:   { eyebrow: "text-[#83d7b6]", rule: "bg-[#83d7b6]" },
  blue:   { eyebrow: "text-[#83d7b6]", rule: "bg-[#83d7b6]" },
  purple: { eyebrow: "text-[#83d7b6]", rule: "bg-[#83d7b6]" },
  orange: { eyebrow: "text-[#d08a5d]", rule: "bg-[#d08a5d]" },
  yellow: { eyebrow: "text-[#d08a5d]", rule: "bg-[#d08a5d]" },
  green:  { eyebrow: "text-[#83d7b6]", rule: "bg-[#83d7b6]" },
  gray:   { eyebrow: "text-[#8da59b]", rule: "bg-[#8da59b]" },
};

const ease = [0.25, 0.1, 0.25, 1] as const;

export function PageHeader({
  eyebrow,
  title,
  description,
  children,
  className,
  accent = "cyan",
}: PageHeaderProps) {
  const styles = accentStyles[accent];

  return (
    <div className={cn("relative mb-10 max-w-3xl", className)}>
      {eyebrow && (
        <motion.div
          className="mb-4 flex items-center gap-2.5"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, ease }}
        >
          <span className={cn("w-3 h-px rounded-full opacity-80", styles.rule)} />
          <p className={cn("font-mono text-[10px] font-medium tracking-[0.06em]", styles.eyebrow)}>
            {eyebrow}
          </p>
        </motion.div>
      )}

      <motion.h1
        className="mb-4 text-3xl font-medium leading-tight tracking-[-0.035em] text-[#e5eee9] sm:text-5xl"
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, ease, delay: 0.05 }}
      >
        {title}
      </motion.h1>

      {description && (
        <motion.p
          className="max-w-2xl text-[15px] leading-7 text-[#8da59b]"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease, delay: 0.1 }}
        >
          {description}
        </motion.p>
      )}

      {children}
    </div>
  );
}
