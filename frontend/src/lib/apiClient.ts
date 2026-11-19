export interface ApiCallResult {
  endpoint: string;
  method: string;
  status: number;
  latencyMs: number;
  data: unknown;
  ok: boolean;
}

export async function invokeProtectedApi(
  baseUrl: string,
  endpoint: string,
  method: "GET" | "POST",
  accessToken?: string,
  body?: Record<string, unknown>
): Promise<ApiCallResult> {
  const startedAt = performance.now();
  const headers: Record<string, string> = {
    Accept: "application/json"
  };

  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }
  if (body) {
    headers["Content-Type"] = "application/json";
  }

  try {
    const response = await fetch(`${baseUrl}${endpoint}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });

    const latencyMs = Math.round(performance.now() - startedAt);
    let data: unknown;
    try {
      data = await response.json();
    } catch {
      data = { raw: await response.text() };
    }

    return {
      endpoint,
      method,
      status: response.status,
      latencyMs,
      data,
      ok: response.ok
    };
  } catch (err) {
    return {
      endpoint,
      method,
      status: 0,
      latencyMs: Math.round(performance.now() - startedAt),
      data: {
        error: "network_unreachable",
        message:
          err instanceof Error
            ? err.message
            : "Backend resource server could not be reached. Start backend with `npm run dev:backend`."
      },
      ok: false
    };
  }
}
