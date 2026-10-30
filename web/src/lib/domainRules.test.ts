import { decodeDomainCsv, encodeDomainCsv, migrateDomainRules, normalizeDomainRow, normalizeDomainRows, MAX_CSV_BYTES } from "./domainRules";

const row = {domain:"example.net",type:"wildcard" as const,action:"monitor" as const};
it("round trips order, actions and normalized IDNA domains", () => {
  const rows = [row, {domain:"xn--bcher-kva.de",type:"simple" as const,action:"allow" as const}];
  expect(decodeDomainCsv(encodeDomainCsv(rows))).toEqual(rows);
  expect(normalizeDomainRow({...row,domain:"BÜCHER.de"})).toEqual({...row,domain:"xn--bcher-kva.de"});
});
it("accepts UTF8 BOM, semicolons, quoting and normal/log aliases", () => {
  expect(decodeDomainCsv('\uFEFFdomain;type;action\r\n"example.net";normal;log\r\n')).toEqual([{...row,type:"simple"}]);
});
it.each([
  ["domain,type,action\nhttps://bad.example,simple,block",/linha 2/i],
  ["domain,type,action\nexample.net,regex,block",/linha 2/i],
  ['domain,type,action\n"example.net,simple,block',/CSV/i],
  ["domain,type,action\nexample.net,simple,allow\nexample.net,simple,block",/linha 3/i],
  ["domain,type,action\n=cmd(),simple,block",/linha 2/i],
  ["host,kind,action\nexample.net,simple,block",/cabeçalho/i],
])("rejects malformed CSV without partial rows", (csv, error) => { expect(() => decodeDomainCsv(csv)).toThrow(error); });
it("migrates legacy allowed-before-blocked order and strips only the wildcard prefix", () => {
  expect(migrateDomainRules({allowed:["*.example.net"],blocked:["example.net"]})).toEqual([
    {...row,action:"allow"}, {...row,type:"simple",action:"block"},
  ]);
});
it.each(["127.0.0.1", "localhost", "example.net.", "user@example.net", "example.net/path", "*.example.net", "example net.com", "", "http://example.net", "-bad.example"])("rejects unsupported domain input %s", (domain) => {
  expect(() => normalizeDomainRow({...row,domain})).toThrow(/domínio válido/i);
});
it("rejects unknown row fields, malformed values and duplicate normalized patterns", () => {
  expect(() => normalizeDomainRow({...row,enabled:true})).toThrow();
  expect(() => normalizeDomainRow(null)).toThrow();
  expect(() => normalizeDomainRows([row,{...row,domain:"EXAMPLE.NET",action:"allow"}])).toThrow(/já existe/i);
  expect(() => normalizeDomainRows(Array.from({length:10001}, () => row))).toThrow(/10.000/);
});
it("keeps published ordered records and collapses only shadowed exact legacy duplicates", () => {
  expect(migrateDomainRules({domain_rules:[row]})).toEqual([row]);
  expect(migrateDomainRules({allowed:["example.net",null],blocked:["example.net"]})).toEqual([{...row,type:"simple",action:"allow"}]);
  expect(migrateDomainRules({})).toEqual([]);
});
it.each([
  ["domain,type,action\n", /não contém/],
  ['domain,type,action\n"example.net"x,simple,allow', /CSV inválido/],
  ['domain,type,action\nexa"mple.net,simple,allow', /CSV inválido/],
  ['domain,type,action\n"exa""mple.net",simple,allow', /Linha 2/],
  ['domain,type,action\n"exa\nmple.net",simple,allow', /Linha 2/],
  ['domain,type,action\nexample.net,simple', /três colunas/],
])("reports CSV structure errors %s", (csv,error) => {expect(() => decodeDomainCsv(csv)).toThrow(error);});
it("rejects oversized files and excessive rows before import", () => {
  expect(() => decodeDomainCsv("x".repeat(MAX_CSV_BYTES+1))).toThrow(/2 MB/);
  expect(() => decodeDomainCsv("domain,type,action\n"+"example.net,simple,allow\n".repeat(10001))).toThrow(/10.000/);
});
