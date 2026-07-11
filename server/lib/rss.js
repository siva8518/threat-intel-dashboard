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

function extractAttr(tagXml, attrName) {
  const match = tagXml.match(new RegExp(`${attrName}\\s*=\\s*"([^"]*)"`, "i"));
  return match ? match[1] : null;
}

/**
 * Atom's <link> is a self-closing tag carrying an href attribute, not a text
 * node like RSS's <link>text</link> -- and one <entry> can have several
 * (rel="alternate", "self", "related", ...). Per the Atom spec a <link> with
 * no rel defaults to "alternate" (the human-readable page), so prefer an
 * explicit or implied "alternate" link, else the first href found, else fall
 * back to <id> (Atom entries always have one, and it's a valid URL on many
 * feeds even when no clean "alternate" link exists).
 */
function extractAtomLink(entryXml) {
  const links = (entryXml.match(/<link\b[^>]*\/?>/gi) || [])
    .map((tag) => ({ rel: extractAttr(tag, "rel"), href: extractAttr(tag, "href") }))
    .filter((l) => l.href);
  const alternate = links.find((l) => !l.rel || l.rel === "alternate");
  return (alternate ?? links[0])?.href ?? extractTag(entryXml, "id") ?? "#";
}

/** Atom 1.0 (<entry>-based) equivalent of parseRss -- see parseFeed below for auto-detection between the two. */
export function parseAtom(xml) {
  const entries = xml.match(/<entry[^>]*>[\s\S]*?<\/entry>/gi) || [];
  return entries.map((entryXml) => ({
    title: extractTag(entryXml, "title") ?? "Untitled",
    link: extractAtomLink(entryXml),
    // Atom has no <pubDate> -- <published> (creation time) is closer to
    // RSS's <pubDate> semantics than <updated> (last-edited time, which
    // every entry has but which bumps on any edit, not just new posts).
    pubDate: extractTag(entryXml, "published") ?? extractTag(entryXml, "updated"),
  }));
}

/**
 * Auto-detects RSS 2.0/1.0 (<item>-based) vs Atom 1.0 (<entry>-based) and
 * parses accordingly. Feeds fetched by server/connectors/newsFeeds.js are a
 * mix of both, and callers there don't know or care which format a given
 * publisher happens to use -- this is what let feeds like Schneier on
 * Security and The Register (both Atom-only) go from "unsupported format" to
 * just another entry in that connector's FEEDS list.
 */
export function parseFeed(xml) {
  return /<entry[\s>]/i.test(xml) ? parseAtom(xml) : parseRss(xml);
}
