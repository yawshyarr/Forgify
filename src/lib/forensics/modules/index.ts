import type { ForensicModule } from "@/lib/forensics/types";
import { copyMoveModule, pixelModule } from "@/lib/forensics/modules/pixel";
import { aigcModule, compressionModule } from "@/lib/forensics/modules/signal";
import { metadataModule, provenanceModule, signatureModule } from "@/lib/forensics/modules/metadata";
import { layoutModule, ocrModule, qrModule, semanticModule } from "@/lib/forensics/modules/content";

/**
 * Ordered execution plan for the forensic pipeline. Adding a real detector
 * later means appending one `ForensicModule` here — fusion, persistence, the
 * API envelope and every UI surface pick it up automatically.
 */
export const MODULES: ForensicModule[] = [
  pixelModule,
  compressionModule,
  metadataModule,
  provenanceModule,
  ocrModule,
  layoutModule,
  copyMoveModule,
  signatureModule,
  qrModule,
  semanticModule,
  aigcModule,
];

export const MODULE_MAP = MODULES.reduce<Record<string, ForensicModule>>((acc, m) => {
  acc[m.id] = m;
  return acc;
}, {});
