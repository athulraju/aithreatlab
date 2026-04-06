import { cn } from "@/lib/utils";

interface BadgeProps {
  children: React.ReactNode;
  variant?: "default" | "cyan" | "blue" | "purple" | "green" | "red" | "orange" | "yellow" | "gray";
  size?: "sm" | "md";
  className?: string;
}

const variantStyles = {
  default: "text-gray-300 bg-white/5 border-white/10",
  cyan: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
  blue: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  purple: "text-purple-400 bg-purple-400/10 border-purple-400/20",
  green: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
  red: "text-red-400 bg-red-400/10 border-red-400/20",
  orange: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  yellow: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  gray: "text-gray-500 bg-gray-500/10 border-gray-500/20",
};

export function Badge({ children, variant = "default", size = "sm", className }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center font-medium border rounded-md",
        size === "sm" ? "text-xs px-2 py-0.5" : "text-sm px-2.5 py-1",
        variantStyles[variant],
        className
      )}
    >
      {children}
    </span>
  );
}
