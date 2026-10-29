import { decodeDomainCsv, encodeDomainCsv, migrateDomainRules, normalizeDomainRow } from "./domainRules";

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
