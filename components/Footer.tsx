import Link from "next/link";
import { Shield, Github, Twitter } from "lucide-react";

export function Footer() {
  return (
    <footer className="border-t border-white/[0.06] bg-[#080810] mt-20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-10">
          {/* Brand */}
          <div className="md:col-span-2">
            <div className="flex items-center gap-2.5 mb-4">
              <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                <Shield className="w-4 h-4 text-white" />
              </div>
              <span className="font-semibold text-white text-sm">
                Detect<span className="text-cyan-400">Lab</span>
              </span>
            </div>
            <p className="text-gray-500 text-sm leading-relaxed max-w-xs">
              A platform for building, translating, testing, and operationalizing detections across Sigma, Splunk, and PySpark.
            </p>
          </div>

          {/* Links */}
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">Platform</p>
            <div className="space-y-2.5">
              {[
                { href: "/converter", label: "Converter" },
                { href: "/detections", label: "Detection Library" },
                { href: "/coverage", label: "Coverage Framework" },
                { href: "/playground", label: "Playground" },
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
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">Research</p>
            <div className="space-y-2.5">
              {[
                { href: "/ai-security", label: "AI Security" },
                { href: "/research", label: "Research" },
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
            © 2024 DetectLab. Detection engineering platform.
          </p>
          <div className="flex items-center gap-4">
            <span className="text-xs text-gray-600">Built for defenders.</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
