/**
 * Ported from the original src/lib/cpe.ts (now removed from the frontend --
 * this parsing runs server-side in the nvd connector instead). See git
 * history / README for the story behind extractVendorProductFromAffected:
 * many CVEs only carry vendor/product on cve.affected[], not the
 * configurations/CPE structure, which originally caused every row in the
 * CVE table to show "Unknown" until this fallback chain was added.
 */
export function extractVendorProduct(criteria) {
  for (const cpe of criteria) {
    const parts = cpe.split(":");
    if (parts.length >= 5 && parts[0] === "cpe") {
      const vendor = decodeCpeComponent(parts[3]);
      const product = decodeCpeComponent(parts[4]);
      if (vendor && vendor !== "*") return { vendor: titleCase(vendor), product: titleCase(product) };
    }
  }
  return { vendor: "Unknown", product: "Unknown" };
}

export function extractVendorProductFromAffected(affected) {
  for (const entry of affected ?? []) {
    for (const data of entry.affectedData ?? []) {
      if (data.vendor && data.vendor.toLowerCase() !== "n/a") {
        const product = data.product && data.product.toLowerCase() !== "n/a" ? data.product : "Unknown";
        return { vendor: titleCase(data.vendor), product: product === "Unknown" ? product : titleCase(product) };
      }
    }
  }
  return null;
}

function decodeCpeComponent(value) {
  if (!value) return "";
  return value.replace(/_/g, " ").replace(/\\(.)/g, "$1");
}

function titleCase(value) {
  return value.replace(/\b\w/g, (c) => c.toUpperCase());
}
