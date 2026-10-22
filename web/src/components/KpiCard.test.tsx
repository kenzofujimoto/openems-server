import { render, screen } from "@testing-library/react";
import { Monitor } from "lucide-react";
import { KpiCard } from "./KpiCard";

describe("KpiCard", () => {
  it("shows the label, value and a positive delta", () => {
    render(<KpiCard label="Online" value="9" icon={Monitor} delta={{ text: "+12%", tone: "up" }} caption="vs. semana passada" />);
    expect(screen.getByText("Online")).toBeInTheDocument();
    expect(screen.getByText("9")).toBeInTheDocument();
    expect(screen.getByText("+12%")).toHaveAttribute("data-tone", "up");
    expect(screen.getByText("vs. semana passada")).toBeInTheDocument();
  });

  it("can invert the meaning of a delta so that growth in errors is bad", () => {
    render(<KpiCard label="Erros" value="3" icon={Monitor} delta={{ text: "+50%", tone: "up" }} invertTone />);
    expect(screen.getByText("+50%")).toHaveAttribute("data-good", "false");
  });

  it("hides the comparison caption when there is no delta", () => {
    render(<KpiCard label="Total" value="10" icon={Monitor} caption="vs. semana passada" />);
    expect(screen.getByText("10")).toBeInTheDocument();
    expect(screen.queryByText("vs. semana passada")).not.toBeInTheDocument();
  });
});
