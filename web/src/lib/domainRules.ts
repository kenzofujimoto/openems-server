import { z } from "zod";

export interface DomainRow {
  domain: string;
  type: "simple" | "wildcard";
  action: "allow" | "block" | "monitor";
}
export const MAX_DOMAIN_ROWS = 10_000;
export const MAX_CSV_BYTES = 2 * 1024 * 1024;

export function normalizeDomainRow(value: unknown): DomainRow {
  const row = z.object({domain:z.string(), type:z.enum(["simple", "wildcard"]), action:z.enum(["allow", "block", "monitor"])}).strict().safeParse(value);
  if (!row.success) throw new Error("Informe domínio, tipo Simples/Wildcard e ação Permitir/Bloquear/Monitorar.");
  const host = row.data.domain.trim();
  let domain = "";
  try { domain = new URL(`http://${host}`).hostname; } catch { /* The common validation below reports malformed domains. */ }
  if (/[\s/:@?#%\\*]/.test(host) || host.endsWith(".") || !domain.includes(".") || !z.hostname().safeParse(domain).success || z.ipv4().safeParse(domain).success) {
    throw new Error("Informe um domínio válido, como example.com, sem URL, caminho ou *. Selecione Wildcard para incluir subdomínios.");
  }
  return {...row.data, domain:domain.toLowerCase()};
}

export function normalizeDomainRows(values: unknown[]): DomainRow[] {
  if (values.length > MAX_DOMAIN_ROWS) throw new Error("A política aceita no máximo 10.000 domínios.");
  const seen = new Set<string>();
  return values.map((value) => {
    const row = normalizeDomainRow(value);
    const key = `${row.type}:${row.domain}`;
    if (seen.has(key)) throw new Error(`O domínio ${row.domain} já existe com esse tipo. Edite a regra existente.`);
    seen.add(key);
    return row;
  });
}

export function migrateDomainRules(settings: Record<string, unknown>): DomainRow[] {
  if (Array.isArray(settings.domain_rules)) return normalizeDomainRows(settings.domain_rules);
  const rows: DomainRow[] = [];
  const seen = new Set<string>();
  for (const [field, action] of [["allowed", "allow"], ["blocked", "block"]] as const) {
    const values = settings[field];
    if (!Array.isArray(values)) continue;
    for (const value of values) {
      if (typeof value !== "string") continue;
      const wildcard = value.startsWith("*.");
      const row = normalizeDomainRow({domain:wildcard ? value.slice(2) : value, type:wildcard ? "wildcard" : "simple", action});
      const key = `${row.type}:${row.domain}`;
      // A legacy allow and block for the same pattern always resolved to allow.
      if (!seen.has(key)) { rows.push(row); seen.add(key); }
    }
  }
  return normalizeDomainRows(rows);
}

interface CsvRecord { fields: string[]; line: number }

function parseCsv(text: string): CsvRecord[] {
  const source = text.replace(/^\uFEFF/, "");
  const header = source.split(/\r?\n/, 1)[0] ?? "";
  const separator = header.includes(";") && !header.includes(",") ? ";" : ",";
  const records: CsvRecord[] = [];
  let fields: string[] = []; let field = ""; let quoted = false; let closed = false;
  let line = 1; let startLine = 1;
  const finishField = () => { fields.push(field); field = ""; closed = false; };
  const finishRecord = () => {
    finishField();
    if (fields.some((value) => value.trim())) records.push({fields, line:startLine});
    fields = [];
  };
  for (let index = 0; index < source.length; index++) {
    const character = source[index];
    if (quoted) {
      if (character === '"') {
        if (source[index + 1] === '"') { field += '"'; index++; }
        else { quoted = false; closed = true; }
      } else { field += character; if (character === "\n") line++; }
      continue;
    }
    if (character === separator) { finishField(); continue; }
    if (character === "\n" || character === "\r") {
      if (character === "\r" && source[index + 1] === "\n") index++;
      finishRecord(); line++; startLine = line; continue;
    }
    if (closed) throw new Error(`CSV inválido na linha ${line}: caractere após aspas.`);
    if (character === '"') {
      if (field) throw new Error(`CSV inválido na linha ${line}: aspas fora de um campo.`);
      quoted = true;
    } else { field += character; }
  }
  if (quoted) throw new Error(`CSV inválido na linha ${startLine}: aspas não fechadas.`);
  if (field || fields.length || closed) finishRecord();
  return records;
}

export function decodeDomainCsv(text: string): DomainRow[] {
  if (new TextEncoder().encode(text).length > MAX_CSV_BYTES) throw new Error("O CSV deve ter no máximo 2 MB.");
  const [header, ...records] = parseCsv(text);
  if (header?.fields.map((field) => field.trim().toLowerCase()).join(",") !== "domain,type,action") {
    throw new Error("Cabeçalho esperado: domain,type,action.");
  }
  if (!records.length) throw new Error("O CSV não contém domínios.");
  if (records.length > MAX_DOMAIN_ROWS) throw new Error("O CSV aceita no máximo 10.000 domínios.");
  const seen = new Set<string>();
  return records.map(({fields, line}) => {
    try {
      if (fields.length !== 3) throw new Error("Esperadas três colunas: domain,type,action.");
      const [domain, rawType, rawAction] = fields.map((field) => field.trim());
      const type = rawType?.toLowerCase(); const action = rawAction?.toLowerCase();
      const row = normalizeDomainRow({domain, type:type === "normal" ? "simple" : type, action:action === "log" ? "monitor" : action});
      const key = `${row.type}:${row.domain}`;
      if (seen.has(key)) throw new Error("Domínio e tipo duplicados; mantenha uma regra para esse padrão.");
      seen.add(key);
      return row;
    } catch (error) { throw new Error(`Linha ${line}: ${error instanceof Error ? error.message : "Domínio inválido."}`, {cause:error}); }
  });
}

export function encodeDomainCsv(rows: DomainRow[]): string {
  const fields = [["domain", "type", "action"], ...normalizeDomainRows(rows).map((row) => [row.domain, row.type, row.action])];
  return "\uFEFF" + fields.map((row) => row.map((value) => `"${value.replaceAll('"', '""')}"`).join(",")).join("\r\n") + "\r\n";
}
