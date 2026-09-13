export async function fetchWithTimeout<T>(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  readResponse: (response: Response) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new DOMException("The operation timed out", "TimeoutError"));
  }, timeoutMs);
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    return await readResponse(response);
  } finally {
    // Pending timers prevent Durable Object hibernation. Keep the deadline
    // through body consumption, then release it on both success and failure.
    clearTimeout(timer);
  }
}
