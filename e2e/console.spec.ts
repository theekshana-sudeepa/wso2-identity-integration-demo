import { expect, test } from "@playwright/test";

test.describe("Choreo Labs / WSO2 Identity Integration Console E2E", () => {
  test("verifies Demo Admin RBAC 200, Attack Lab alg:none 401, AI Agent MCP 403, and CIBA Step-Up 200", async ({
    page
  }) => {
    await page.goto("/");

    await expect(
      page.getByRole("heading", { name: /WSO2 Identity Integration Console/i })
    ).toBeVisible();

    // 1. Load Demo Admin and invoke Admin Audit Logs endpoint -> 200
    await page.getByRole("button", { name: /Demo Admin/i }).click();
    await page.getByRole("button", { name: /Admin Audit Logs/i }).click();
    await expect(page.getByText(/HTTP 200/i).first()).toBeVisible();

    // 2. Open Attack Lab and inject JWT Alg Downgrade (alg:none) -> 401
    await page
      .getByRole("button", { name: /Break-the-Flow Security/i })
      .click();
    await page.getByRole("radio", { name: /JWT Alg Downgrade/i }).click();
    await expect(page.getByText(/401 Unauthorized/i).first()).toBeVisible();

    // Reset baseline
    await page.getByRole("button", { name: /Reset Baseline/i }).click();

    // 3. Switch to AI Agent + MCP (6-Stage) and test issue_refund -> 403
    await page.getByRole("tab", { name: /AI Agent \+ MCP/i }).click();
    const refundCard = page
      .locator(".mcp-tool-card")
      .filter({ hasText: "issue_refund" });
    await refundCard.getByRole("button", { name: /Execute Tool/i }).click();
    await expect(page.getByText(/scope_escalation_blocked/i).first()).toBeVisible();

    // 4. Execute export_all_users -> 403 CIBA card appears -> click Approve -> 200 ALLOWED
    const exportCard = page
      .locator(".mcp-tool-card")
      .filter({ hasText: "export_all_users" });
    await exportCard.getByRole("button", { name: /Execute Tool/i }).click();
    const approveBtn = page.getByRole("button", {
      name: /Approve Step-Up Consent/i
    });
    await expect(approveBtn).toBeVisible();
    await approveBtn.click();
    await expect(page.getByText(/exp_verified/i).first()).toBeVisible();
  });
});
