import { cn } from "@/lib/utils";

interface PageHeaderProps {
  eyebrow?: string;
  title: string;
  description?: string;
  children?: React.ReactNode;
  className?: string;
}

export function PageHeader({ eyebrow, title, description, children, className }: PageHeaderProps) {
  return (
    <div className={cn("mb-10", className)}>
      {eyebrow && (
        <p className="text-xs font-semibold text-cyan-400 uppercase tracking-widest mb-3">
          {eyebrow}
        </p>
      )}
      <h1 className="text-3xl sm:text-4xl font-bold text-white tracking-tight mb-4">
        {title}
      </h1>
      {description && (
        <p className="text-gray-400 text-lg max-w-2xl leading-relaxed">{description}</p>
      )}
      {children}
    </div>
  );
}
