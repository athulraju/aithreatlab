import { HomeExperience } from "@/components/home/HomeExperience";
import { coreDetections } from "@/lib/data/detections/core";
import { researchSections } from "@/lib/data/research";

export default function HomePage() {
  const featuredDetection = coreDetections[0];
  const featuredResearch = researchSections.flatMap((section) =>
    section.links.map((item) => ({ ...item, section: section.title }))
  ).slice(0, 3);

  return (
    <HomeExperience
      detection={{
        id: featuredDetection.id,
        title: featuredDetection.title,
        category: featuredDetection.category,
        severity: featuredDetection.severity,
        sigma: featuredDetection.sigma,
      }}
      research={featuredResearch}
    />
  );
}
