/** Build-time identity. `VITE_BRAND=rsm` produces the RSM Brasil edition; the default is OpenEMS. */
export type BrandId = "openems" | "rsm";

interface Brand { id: BrandId; title: string; tagline: string }

const BRANDS: Record<BrandId, Brand> = {
  openems: { id: "openems", title: "OpenEMS", tagline: "Gerencie políticas de endpoint com confirmação de cada agente." },
  rsm: { id: "rsm", title: "RSM Endpoint Management", tagline: "Gestão de endpoints RSM Brasil com confirmação de cada agente." },
};

export function resolveBrand(value: string | undefined): Brand {
  return value === "rsm" ? BRANDS.rsm : BRANDS.openems;
}

export const BRAND = resolveBrand(import.meta.env.VITE_BRAND);
