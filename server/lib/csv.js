/**
 * Minimal RFC4180 CSV line splitter -- handles quoted fields with embedded
 * commas/quotes (Exploit-DB's description column has both), without pulling
 * in a dependency for one feed. Mirrors server/lib/rss.js's philosophy of a
 * small hand-rolled parser for exactly the shape one upstream source uses.
 */
function splitCsvLine(line) {
  const fields = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (inQuotes) {
      if (char === '"' && line[i + 1] === '"') {
        field += '"';
        i++;
      } else if (char === '"') {
        inQuotes = false;
      } else {
        field += char;
      }
    } else if (char === '"') {
      inQuotes = true;
    } else if (char === ",") {
      fields.push(field);
      field = "";
    } else {
      field += char;
    }
  }
  fields.push(field);
  return fields;
}

/** Parses a full CSV document (header row + data rows) into an array of objects keyed by header. */
export function parseCsv(text) {
  const lines = text.split(/\r\n|\n/).filter((line) => line.length > 0);
  if (lines.length === 0) return [];

  const header = splitCsvLine(lines[0]);
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const values = splitCsvLine(lines[i]);
    if (values.length !== header.length) continue; // malformed row (rare, embedded newline inside a quoted field) -- skip rather than misalign columns
    const row = {};
    header.forEach((key, idx) => (row[key] = values[idx]));
    rows.push(row);
  }
  return rows;
}
