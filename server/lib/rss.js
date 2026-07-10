/**
 * Minimal RSS 2.0 parser using regex instead of an XML library. This mirrors
 * the browser version that used to live at src/lib/rss.ts (DOMParser-based),
 * but Node has no built-in DOMParser -- this is the server-side equivalent,
 * kept deliberately small since we only ever need title/link/pubDate.
 */
function extractTag(itemXml, tagName) {
  const regex = new RegExp(`<${tagName}[^>]*>([\\s\\S]*?)<\\/${tagName}>`, "i");
  const match = itemXml.match(regex);
  if (!match) return null;

  let content = match[1].trim();
  const cdata = content.match(/^<!\[CDATA\[([\s\S]*?)\]\]>$/);
  if (cdata) content = cdata[1].trim();

  return content
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&(#39|apos);/g, "'")
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

export function parseRss(xml) {
  const items = xml.match(/<item[^>]*>[\s\S]*?<\/item>/gi) || [];
  return items.map((itemXml) => ({
    title: extractTag(itemXml, "title") ?? "Untitled",
    link: extractTag(itemXml, "link") ?? "#",
    // RSS 2.0 uses <pubDate> (RFC 822); RSS 1.0/RDF feeds (e.g. JPCERT) use
    // Dublin Core's <dc:date> (ISO 8601) instead -- fall back to it so those
    // feeds don't all report a fabricated "just now" timestamp.
    pubDate: extractTag(itemXml, "pubDate") ?? extractTag(itemXml, "dc:date"),
  }));
}
