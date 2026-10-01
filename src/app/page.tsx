import { SiteFooter, SiteHeader } from "@/components/site/chrome";
import { Hero } from "@/components/landing/Hero";
import { LayerStack, Methodology, Pipeline, ReferenceModes, ReportPreview, SecurityLimits, WhyFails } from "@/components/landing/Sections";
import { EngineCards } from "@/components/landing/EngineCards";
import { EvidenceFusion, RegionDemo } from "@/components/landing/Interactive";
import { FinalCta } from "@/components/landing/FinalCta";

export default function LandingPage() {
  return (
    <>
      <SiteHeader />
      <main>
        <Hero />
        <WhyFails />
        <LayerStack />
        <Pipeline />
        <EngineCards />
        <EvidenceFusion />
        <RegionDemo />
        <ReportPreview />
        <ReferenceModes />
        <Methodology />
        <SecurityLimits />
        <FinalCta />
      </main>
      <SiteFooter />
    </>
  );
}
