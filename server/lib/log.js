const LEVELS = { info: "INFO", warn: "WARN", error: "ERROR" };

function line(level, sourceId, message) {
  const timestamp = new Date().toISOString();
  return `[${timestamp}] [${LEVELS[level]}] [${sourceId}] ${message}`;
}

export const log = {
  info: (sourceId, message) => console.log(line("info", sourceId, message)),
  warn: (sourceId, message) => console.warn(line("warn", sourceId, message)),
  error: (sourceId, message) => console.error(line("error", sourceId, message)),
};
