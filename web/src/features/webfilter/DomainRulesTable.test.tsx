import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { DomainRulesTable } from "./DomainRulesTable";
import { type DomainRow, MAX_CSV_BYTES } from "@/lib/domainRules";

const first:DomainRow = {domain:"example.net",type:"simple",action:"block"};
function Table({initial=[first],readonly=false}: {initial?:DomainRow[];readonly?:boolean}) {
  const [rows,setRows]=useState(initial);
  return <DomainRulesTable rows={rows} onChange={setRows} readonly={readonly} />;
}
afterEach(() => {vi.restoreAllMocks();});

it("deletes a row, shows empty state and opens a keyboard accessible editor", async () => {
  const user=userEvent.setup(); render(<Table />);
  await user.click(screen.getByRole("button",{name:"Excluir example.net"}));
  expect(screen.getByText(/Nenhuma regra/)).toBeInTheDocument();
  const add=screen.getByRole("button",{name:"Adicionar domínio"}); add.focus();
  await user.keyboard("{Enter}");
  expect(screen.getByLabelText("Domínio")).toHaveFocus();
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(add).toHaveFocus();
});

it("prevents duplicate edits and cancels without changing the table", async () => {
  const user=userEvent.setup(); render(<Table />);
  await user.click(screen.getByRole("button",{name:"Adicionar domínio"}));
  await user.type(screen.getByLabelText("Domínio"),"example.net");
  await user.click(screen.getByRole("button",{name:"Salvar domínio"}));
  expect(screen.getByRole("alert")).toHaveTextContent(/já existe/i);
  await user.click(screen.getByRole("button",{name:"Cancelar"}));
  expect(screen.getAllByRole("row")).toHaveLength(2);
});

it("exports actual ordered rows and releases the URL even if saving fails", async () => {
  const create=vi.spyOn(URL,"createObjectURL").mockReturnValue("blob:domains");
  const revoke=vi.spyOn(URL,"revokeObjectURL").mockImplementation(() => {});
  const click=vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(() => {});
  const user=userEvent.setup(); render(<Table initial={[first,{...first,domain:"example.org",action:"monitor"}]} />);
  await user.click(screen.getByRole("button",{name:"Exportar CSV"}));
  const blob=create.mock.calls[0]?.[0] as Blob;
  expect(await blob.text()).toContain('"example.org","simple","monitor"');
  expect(revoke).toHaveBeenCalledWith("blob:domains");
  click.mockImplementation(() => {throw new Error("Save failed");});
  await user.click(screen.getByRole("button",{name:"Exportar CSV"}));
  expect(screen.getByRole("alert")).toHaveTextContent("Save failed");
  expect(revoke).toHaveBeenCalledTimes(2);
});

it("filters and paginates large tables without changing global order", async () => {
  const rows=Array.from({length:51},(_,index) => ({...first,domain:`site${index}.example`}));
  const user=userEvent.setup(); render(<Table initial={rows} />);
  expect(screen.queryByText("site50.example")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button",{name:"Próxima"}));
  expect(screen.getByText("site50.example")).toBeInTheDocument();
  expect(screen.getByRole("button",{name:"Mover site50.example para baixo"})).toBeDisabled();
  await user.click(screen.getByRole("button",{name:"Anterior"}));
  await user.type(screen.getByLabelText("Buscar domínio"),"site50");
  await user.click(screen.getByRole("button",{name:"Mover site50.example para cima"}));
  expect(within(screen.getByRole("row",{name:/site50/})).getByText("50")).toBeInTheDocument();
  await user.clear(screen.getByLabelText("Buscar domínio"));
  await user.type(screen.getByLabelText("Buscar domínio"),"missing");
  expect(screen.getByText("Nenhum domínio encontrado.")).toBeInTheDocument();
});

it("handles file limits, conflicts and read failures without changing existing rows", async () => {
  const user=userEvent.setup(); render(<Table />);
  const upload=screen.getByLabelText("Importar CSV");
  const huge=new File(["domain,type,action"],"huge.csv",{type:"text/csv"});
  Object.defineProperty(huge,"size",{value:MAX_CSV_BYTES+1});
  await user.upload(upload,huge);
  expect(await screen.findByRole("alert")).toHaveTextContent(/2 MB/);
  const broken=new File(["data"],"broken.csv",{type:"text/csv"});
  vi.spyOn(broken,"text").mockRejectedValue(new Error("File unreadable"));
  await user.upload(upload,broken);
  expect(await screen.findByRole("alert")).toHaveTextContent("File unreadable");
  await user.upload(upload,new File(["domain,type,action\nexample.net,simple,allow"],"duplicate.csv",{type:"text/csv"}));
  expect(await screen.findByRole("alert")).toHaveTextContent(/já existe/);
  expect(screen.getAllByRole("row")).toHaveLength(2);
});

it("lets viewers inspect rows without mutation or import controls", () => {
  render(<Table readonly />);
  expect(screen.getByText("example.net")).toBeInTheDocument();
  expect(screen.queryByRole("button",{name:/Adicionar|Editar|Excluir|Mover/})).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Importar CSV")).not.toBeInTheDocument();
});
