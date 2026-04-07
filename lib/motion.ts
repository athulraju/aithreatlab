/**
 * Shared Framer Motion variants for consistent animations across the site.
 *
 * Design rules (per UX skill §7 Animation):
 * - Micro-interactions  : 150–200 ms, ease-out
 * - Content reveals     : 350–500 ms, ease-out
 * - Stagger children    : 0.05–0.08 s per item
 * - Exit animations     : ~60–70 % of enter duration
 * - Only animate opacity + transform (never width/height/layout)
 * - Framer Motion respects prefers-reduced-motion automatically
 */

// ── Easing curves ────────────────────────────────────────────────────────────
const ease = [0.25, 0.1, 0.25, 1] as const;      // standard ease
const easeOut = "easeOut" as const;
const easeIn  = "easeIn"  as const;

// ── Page / section entrance ───────────────────────────────────────────────────
export const fadeUp = {
  hidden:  { opacity: 0, y: 18 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.45, ease } },
};

export const fadeIn = {
  hidden:  { opacity: 0 },
  visible: { opacity: 1, transition: { duration: 0.35, ease: easeOut } },
};

export const slideUp = {
  hidden:  { opacity: 0, y: 24 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease } },
  exit:    { opacity: 0, y: -8, transition: { duration: 0.2, ease: easeIn } },
};

// ── Stagger containers ────────────────────────────────────────────────────────
export const staggerContainer = (stagger = 0.06, delay = 0) => ({
  hidden:  {},
  visible: { transition: { staggerChildren: stagger, delayChildren: delay } },
});

export const staggerItem = {
  hidden:  { opacity: 0, y: 14 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.4, ease } },
};

// ── Panel / tab content crossfade ────────────────────────────────────────────
export const panelFade = {
  hidden:  { opacity: 0, x: 6 },
  visible: { opacity: 1, x: 0, transition: { duration: 0.22, ease: easeOut } },
  exit:    { opacity: 0, x: -4, transition: { duration: 0.14, ease: easeIn } },
};

// ── Scale in (cards, modals) ─────────────────────────────────────────────────
export const scaleIn = {
  hidden:  { opacity: 0, scale: 0.97 },
  visible: { opacity: 1, scale: 1, transition: { duration: 0.28, ease } },
  exit:    { opacity: 0, scale: 0.98, transition: { duration: 0.15, ease: easeIn } },
};

// ── Accordion content ─────────────────────────────────────────────────────────
export const accordionContent = {
  hidden:  { opacity: 0, y: -6 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.22, ease: easeOut } },
  exit:    { opacity: 0, y: -4, transition: { duration: 0.15, ease: easeIn } },
};

// ── List reveal (scroll-triggered, whileInView) ───────────────────────────────
export const revealItem = (i = 0) => ({
  hidden:  { opacity: 0, y: 16 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.06, duration: 0.4, ease },
  },
});

// ── Bar chart reveal (scaleX from left) ──────────────────────────────────────
export const barReveal = (delay = 0) => ({
  hidden:  { scaleX: 0, originX: 0 },
  visible: { scaleX: 1, originX: 0, transition: { delay, duration: 0.6, ease } },
});
