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
  cyan:   { eyebrow: "text-cyan-400",   rule: "bg-cyan-500" },
  blue:   { eyebrow: "text-blue-400",   rule: "bg-blue-500" },
  purple: { eyebrow: "text-purple-400", rule: "bg-purple-500" },
  orange: { eyebrow: "text-orange-400", rule: "bg-orange-500" },
  yellow: { eyebrow: "text-yellow-400", rule: "bg-yellow-500" },
  green:  { eyebrow: "text-emerald-400",rule: "bg-emerald-500" },
  gray:   { eyebrow: "text-gray-400",   rule: "bg-gray-600" },
};

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
    <div className={cn("mb-10", className)}>
      {eyebrow && (
        <div className="flex items-center gap-2.5 mb-3">
          {/* Accent rule */}
          <span className={cn("w-3 h-px rounded-full opacity-80", styles.rule)} />
          <p className={cn("text-xs font-semibold uppercase tracking-widest", styles.eyebrow)}>
            {eyebrow}
          </p>
        </div>
      )}
      <h1 className="text-3xl sm:text-4xl font-bold text-white tracking-tight mb-4">
        {title}
      </h1>
      {description && (
        <p className="text-gray-400 text-base max-w-2xl leading-relaxed">{description}</p>
      )}
      {children}
    </div>
  );
}
