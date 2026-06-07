import { ScanResult, Verdict } from "../BaseScanner";
import { LLMScanner } from "../LLMScanner";
import { SECURITY_AUDIT_PROMPT } from "../prompts/securityAuditPrompt";

interface GeminiTextPart {
  text: string;
}

interface GeminiContent {
  role?: string;
  parts: GeminiTextPart[];
}

interface GeminiRequestBody {
  system_instruction: { parts: GeminiTextPart[] };
  contents: GeminiContent[];
  generationConfig: {
    temperature: number;
    maxOutputTokens: number;
  };
}

interface GeminiCandidate {
  content: GeminiContent;
  finishReason: string;
}

interface GeminiSuccessResponse {
  candidates: GeminiCandidate[];
}

interface GeminiErrorDetail {
  code: number;
  message: string;
  status: string;
}

interface GeminiErrorResponse {
  error: GeminiErrorDetail;
}

/**
 * Concrete scanner that sends the harvested code + dependency data
 * to the Google Gemini generative AI API for security analysis.
 */
export class GeminiScanner extends LLMScanner {
  get toolName(): string {
    return `Gemini (${process.env.GEMINI_MODEL ?? GeminiScanner.DEFAULT_MODEL})`;
  }

  private static readonly API_BASE =
    "https://generativelanguage.googleapis.com/v1beta/models";
  private static readonly DEFAULT_MODEL = "gemini-2.5-pro";

  // Checks if the value passed is a valid GeminiErrorResponse and if yes, reduce the value type to GeminiErrorResponse
  private static isGeminiError(value: unknown): value is GeminiErrorResponse {
    if (typeof value !== "object" || value === null) return false;
    if (!("error" in value)) return false;
    const err = (value as GeminiErrorResponse).error;
    return (
      typeof err === "object" && err !== null && typeof err.message === "string"
    );
  }

  // Checks if the value passed is a valid GeminiSuccessResponse and if yes, reduce the value type to GeminiSuccessResponse
  private static isGeminiSuccess(
    value: unknown,
  ): value is GeminiSuccessResponse {
    if (typeof value !== "object" || value === null) return false;
    if (!("candidates" in value)) return false;
    const candidates = (value as GeminiSuccessResponse).candidates;
    return Array.isArray(candidates) && candidates.length > 0;
  }

  async scan(targetDir: string): Promise<ScanResult> {
    // validate env
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error(
        "GEMINI_API_KEY environment variable is not set. " +
        "Add it as a repository secret in GitHub Actions.",
      );
    }

    const model = process.env.GEMINI_MODEL ?? GeminiScanner.DEFAULT_MODEL;

    const payload = this.scrapeDataForScan(targetDir);
    console.log(
      `[GeminiScanner] Scraped ${payload.length} characters of context from ${targetDir}`,
    );

    const llmResponse = await this.callGeminiApi(apiKey, model, payload);
    console.log(
      `[GeminiScanner] Received ${llmResponse.length} character response from ${model}`,
    );

    const verdict = this.parseVerdict(llmResponse);
    const markdownReport = this.buildMarkdownReport(
      model,
      verdict,
      llmResponse,
    );

    return {
      toolName: this.toolName,
      verdict,
      markdownReport,
    };
  }

  /**
   * Send the context payload to the Gemini REST API and return the
   * model's text response.
   */
  private async callGeminiApi(
    apiKey: string,
    model: string,
    userContent: string,
  ): Promise<string> {
    const url = `${GeminiScanner.API_BASE}/${model}:generateContent?key=${apiKey}`;

    const body: GeminiRequestBody = {
      system_instruction: {
        parts: [{ text: SECURITY_AUDIT_PROMPT }],
      },
      contents: [
        {
          role: "user",
          parts: [{ text: userContent }],
        },
      ],
      generationConfig: {
        temperature: 0.1,
        maxOutputTokens: 10000,
      },
    };

    const MAX_RETRIES = 3;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      // retry on transient errors
      if (response.status === 503 || response.status === 429) {
        if (attempt === MAX_RETRIES) {
          throw new Error(`Gemini API unavailable after ${MAX_RETRIES} attempts.`);
        }
        console.log(`[GeminiScanner] ${response.status} — retrying (${attempt}/${MAX_RETRIES})...`);
        await new Promise(r => setTimeout(r, 5000));
        continue;
      }

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Gemini API returned HTTP ${response.status}: ${errorText}`,
        );
      }

      const data: unknown = await response.json();

      // log token usage for cost tracking
      if ("usageMetadata" in (data as object)) {
        const usage = (data as any).usageMetadata;
        console.log(`[GeminiScanner] Tokens — prompt: ${usage.promptTokenCount}, output: ${usage.candidatesTokenCount}`);
      }

      if (GeminiScanner.isGeminiError(data)) {
        throw new Error(
          `Gemini API error [${data.error.code}/${data.error.status}]: ${data.error.message}`,
        );
      }

      if (!GeminiScanner.isGeminiSuccess(data)) {
        throw new Error(
          "Unexpected Gemini API response shape — no candidates returned.",
        );
      }

      // check if response was truncated
      const finishReason = data.candidates[0].finishReason;
      if (finishReason === "MAX_TOKENS") {
        console.warn("[GeminiScanner] Response truncated — consider increasing maxOutputTokens.");
      }

      const parts = data.candidates[0].content.parts;
      if (!parts || parts.length === 0) {
        throw new Error("Gemini API returned an empty response (no parts).");
      }

      return parts.map((p) => p.text).join("");
    }

    throw new Error("Gemini API call failed after all retries.");
  }

  /**
   * Looks for `VERDICT: PASS`, `VERDICT: FAIL`, or `VERDICT: MANUAL_REVIEW`
   * Falls back to `manual_review` if the pattern isn't found.
   */
  private parseVerdict(responseText: string): Verdict {
    const match = responseText.match(/VERDICT:\s*(PASS|FAIL|MANUAL_REVIEW)/i);
    if (!match) {
      console.warn(
        "[GeminiScanner] Could not parse VERDICT from LLM response. " +
        "Defaulting to manual_review.",
      );
      return "manual_review";
    }

    const raw = match[1].toUpperCase();
    switch (raw) {
      case "PASS":
        return "pass";
      case "FAIL":
        return "fail";
      case "MANUAL_REVIEW":
        return "manual_review";
      default:
        return "manual_review";
    }
  }

  /**
   * Build the full Markdown report that gets posted as a comment
   * on the GitHub Issue.
   */
  private buildMarkdownReport(
    model: string,
    verdict: Verdict,
    rawResponse: string,
  ): string {
    const verdictEmoji =
      verdict === "pass" ? "✅" : verdict === "fail" ? "🚨" : "⚠️";
    const timestamp = new Date().toISOString();

    const findingsTable = this.extractSection(rawResponse, "FINDINGS_TABLE");
    const summary = this.extractSection(rawResponse, "SUMMARY");

    return [
      `# ${verdictEmoji} Security Scan Report`,
      "",
      `**Scanner** : \`${model}\``,
      `**Verdict** : ${verdict.toUpperCase()} ${verdictEmoji}`,
      `**Timestamp** : ${timestamp}`,
      "",
      "",
      "## Findings",
      "",
      findingsTable || "_No findings._",
      "",
      "",
      "## Summary",
      "",
      summary || "_No summary provided._",
    ].join("\n");
  }

  private extractSection(text: string, section: string): string {
    const regex = new RegExp(`${section}:\\s*([\\s\\S]*?)(?=\\n[A-Z_]+:|$)`);
    const match = text.match(regex);
    return match ? match[1].trim() : "";
  }
}
