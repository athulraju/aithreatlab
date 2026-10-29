import Link from "next/link";
import { Logo } from "@/components/Logo";

export function Footer() {
  return (
    <footer className="atl-page-lineage border-t border-[#bce2d2]/[0.08] bg-[#030b09]">
      <div className="atl-shell py-14">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-10 mb-12">
          {/* Brand */}
          <div className="md:col-span-3">
            <div className="mb-4">
              <Logo />
            </div>
            <p className="max-w-sm text-sm leading-relaxed text-[#718a80]">
              From security research to operational detection—across AI security, coverage, portable rules, and intelligent analyst workflows.
            </p>
          </div>

          {/* Links */}
          <div>
              <p className="mb-4 text-xs font-medium text-[#83d7b6]">Platform</p>
            <div className="space-y-2.5">
              {[
                { href: "/converter", label: "Converter" },
                { href: "/detections", label: "Detection Library" },
                { href: "/coverage", label: "Coverage Framework" },
                { href: "/playground", label: "Playground" },
                { href: "/agent-skills", label: "Agent Workbench" },
                { href: "/agents/logforge", label: "LogForge AI" },
              ].map((link) => (
                <Link
                  key={link.href}
                  href={link.href}
                  className="block text-sm text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {link.label}
                </Link>
              ))}
            </div>
          </div>

          <div>
              <p className="mb-4 text-xs font-medium text-[#83d7b6]">Research</p>
            <div className="space-y-2.5">
              {[
                { href: "/ai-security", label: "AI Security" },
                { href: "/research", label: "Research" },
                { href: "/research-to-detection", label: "Research to Detection" },
                { href: "/about", label: "About" },
              ].map((link) => (
                <Link
                  key={link.href}
                  href={link.href}
                  className="block text-sm text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {link.label}
                </Link>
              ))}
            </div>
          </div>
        </div>

        <div className="border-t border-white/[0.06] pt-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-xs text-gray-600">
            © {new Date().getFullYear()} AIThreatLab. Detection engineering platform.
          </p>
          <div className="flex items-center gap-4">
            <span className="text-xs text-gray-600">Research-informed. Defender-operated.</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
