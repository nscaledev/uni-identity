import { createHash, randomInt } from 'node:crypto'

export const EXCHANGE_PATH = '/oauth2/v2/exchange'

export type RequestEditor = (request: MutableRequest) => void | Promise<void>

export interface MutableRequest {
  url: string
  init: RequestInit
}

export interface ExchangeRequest {
  organizationId?: string
  projectId?: string
}

export interface ExchangeResponse {
  passport: string
  expiresIn: number
  cached: boolean
}

export interface RetryConfig {
  maxAttempts: number
  retryableStatusCodes: number[]
  retryNetworkErrors: boolean
  minBackoffMs: number
  maxBackoffMs: number
}

export interface CacheConfig {
  enabled: boolean
  defaultTtlMs: number
}

export interface MetricsHooks {
  incTotal?: (result: 'success' | 'cached' | 'error' | 'unauthorized') => void
  observeDuration?: (durationMs: number) => void
}

export interface Options {
  baseUrl: string
  fetchImpl?: typeof fetch
  retry?: Partial<RetryConfig>
  cache?: Partial<CacheConfig>
  requestEditors?: RequestEditor[]
  metrics?: MetricsHooks
  headers?: Record<string, string>
}

interface OAuthErrorPayload {
  error?: string
  error_description?: string
}

interface InternalExchangeResponse {
  passport?: string
  expires_in?: number
}

interface CacheEntry {
  response: ExchangeResponse
  expiresAtMs: number
}

enum RetryClass {
  None,
  Transport,
  Status,
}

export class SourceTokenRequiredError extends Error {
  constructor() {
    super('source token is required')
  }
}

export class BaseUrlRequiredError extends Error {
  constructor() {
    super('base URL is required')
  }
}

export class BuildExchangeRequestError extends Error {
  constructor(message: string) {
    super(`failed to build exchange request: ${message}`)
  }
}

export class EditExchangeRequestError extends Error {
  constructor(message: string) {
    super(`failed to edit exchange request: ${message}`)
  }
}

export class UnauthorizedError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly errorCode: string | undefined,
    public readonly description: string,
  ) {
    super(`passport exchange unauthorized: ${description}`)
  }
}

export class HttpStatusError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly errorCode: string | undefined,
    public readonly description: string,
  ) {
    super(`passport exchange failed with status ${statusCode}: ${description}`)
  }
}

export class MissingPassportError extends Error {
  constructor() {
    super('exchange response missing passport field')
  }
}

export class TransportError extends Error {
  constructor(public readonly causeError: unknown) {
    super(`passport exchange transport failure: ${String(causeError)}`)
  }
}

export class PassportExchangeClient {
  private readonly baseUrl: string
  private readonly fetchImpl: typeof fetch
  private readonly retry: RetryConfig
  private readonly cache: CacheConfig
  private readonly requestEditors: RequestEditor[]
  private readonly metrics: MetricsHooks
  private readonly headers: Record<string, string>
  private readonly cacheEntries = new Map<string, CacheEntry>()

  constructor(options: Options) {
    if (!options.baseUrl.trim()) {
      throw new BaseUrlRequiredError()
    }

    this.baseUrl = options.baseUrl.replace(/\/+$/, '')
    this.fetchImpl = options.fetchImpl ?? fetch
    this.retry = {
      maxAttempts: options.retry?.maxAttempts ?? 2,
      retryableStatusCodes: options.retry?.retryableStatusCodes ?? [502, 503, 504],
      retryNetworkErrors: options.retry?.retryNetworkErrors ?? true,
      minBackoffMs: options.retry?.minBackoffMs ?? 50,
      maxBackoffMs: options.retry?.maxBackoffMs ?? 200,
    }
    this.cache = {
      enabled: options.cache?.enabled ?? false,
      defaultTtlMs: options.cache?.defaultTtlMs ?? 60_000,
    }
    this.requestEditors = options.requestEditors ?? []
    this.metrics = options.metrics ?? {}
    this.headers = options.headers ?? {}
  }

  exchange(sourceToken: string): ExchangeCallBuilder {
    return new ExchangeCallBuilder(this, sourceToken)
  }

  async exchangeWithRequest(
    sourceToken: string,
    request: ExchangeRequest,
    timeoutMs?: number,
    signal?: AbortSignal,
  ): Promise<ExchangeResponse> {
    if (!sourceToken.trim()) {
      throw new SourceTokenRequiredError()
    }

    const startedAtMs = Date.now()
    const cacheKey = exchangeCacheKey(sourceToken, request)
    const cached = this.getCached(cacheKey)
    if (cached) {
      this.incTotal('cached')
      return { ...cached, cached: true }
    }

    let attempt = 1
    while (true) {
      const { result, retryClass, error } = await this.performAttempt(sourceToken, request, timeoutMs, signal)
      if (result) {
        const uncached = { ...result, cached: false }
        this.setCached(cacheKey, uncached)
        this.incTotal('success')
        this.observeDuration(Date.now() - startedAtMs)
        return uncached
      }

      if (!error) {
        throw new Error('unexpected exchange state')
      }

      if (error instanceof UnauthorizedError) {
        this.incTotal('unauthorized')
        this.observeDuration(Date.now() - startedAtMs)
        throw error
      }

      if (this.shouldRetry(attempt, retryClass) && !(signal?.aborted ?? false)) {
        attempt += 1
        const slept = await this.sleepWithSignal(backoffDuration(this.retry.minBackoffMs, this.retry.maxBackoffMs), signal)
        if (!slept) {
          throw new DOMException('The operation was aborted', 'AbortError')
        }
        continue
      }

      this.incTotal('error')
      this.observeDuration(Date.now() - startedAtMs)
      throw error
    }
  }

  private async performAttempt(
    sourceToken: string,
    request: ExchangeRequest,
    timeoutMs?: number,
    signal?: AbortSignal,
  ): Promise<{ result?: ExchangeResponse; retryClass: RetryClass; error?: Error }> {
    let built: MutableRequest
    try {
      built = await this.buildExchangeRequest(sourceToken, request, timeoutMs, signal)
    } catch (error) {
      return { retryClass: RetryClass.None, error: error as Error }
    }

    let response: Response
    try {
      response = await this.fetchImpl(built.url, built.init)
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        return { retryClass: RetryClass.None, error }
      }
      return { retryClass: RetryClass.Transport, error: new TransportError(error) }
    }

    return this.parseExchangeResponse(response)
  }

  private async buildExchangeRequest(
    sourceToken: string,
    request: ExchangeRequest,
    timeoutMs?: number,
    signal?: AbortSignal,
  ): Promise<MutableRequest> {
    let url: URL
    try {
      url = new URL(EXCHANGE_PATH, `${this.baseUrl}/`)
    } catch (error) {
      throw new BuildExchangeRequestError(String(error))
    }

    const form = new URLSearchParams()
    if (request.organizationId) {
      form.set('organizationId', request.organizationId)
    }
    if (request.projectId) {
      form.set('projectId', request.projectId)
    }

    const { signal: requestSignal, cleanup } = createAbortSignal(signal, timeoutMs)

    const mutableRequest: MutableRequest = {
      url: url.toString(),
      init: {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sourceToken}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          ...this.headers,
        },
        body: form.toString(),
        signal: requestSignal,
      },
    }

    try {
      for (const editor of this.requestEditors) {
        await editor(mutableRequest)
      }
    } catch (error) {
      cleanup()
      throw new EditExchangeRequestError(String(error))
    }

    const originalSignal = mutableRequest.init.signal
    if (originalSignal) {
      const finalize = () => cleanup()
      originalSignal.addEventListener('abort', finalize, { once: true })
    } else {
      cleanup()
    }

    return mutableRequest
  }

  private async parseExchangeResponse(response: Response): Promise<{ result?: ExchangeResponse; retryClass: RetryClass; error?: Error }> {
    if (response.ok) {
      const payload = (await response.json()) as InternalExchangeResponse
      const passport = payload.passport?.trim() ?? ''
      if (!passport) {
        return { retryClass: RetryClass.None, error: new MissingPassportError() }
      }
      return {
        retryClass: RetryClass.None,
        result: {
          passport,
          expiresIn: payload.expires_in ?? 0,
          cached: false,
        },
      }
    }

    const oauthError = await parseOAuthError(response)
    const description = oauthError.error_description ?? 'exchange request failed'

    if (response.status === 401) {
      return {
        retryClass: RetryClass.None,
        error: new UnauthorizedError(response.status, oauthError.error, description),
      }
    }

    const statusError = new HttpStatusError(response.status, oauthError.error, description)
    if (response.status >= 500 && this.retry.retryableStatusCodes.includes(response.status)) {
      return { retryClass: RetryClass.Status, error: statusError }
    }

    return { retryClass: RetryClass.None, error: statusError }
  }

  private shouldRetry(attempt: number, retryClass: RetryClass): boolean {
    if (attempt >= this.retry.maxAttempts) {
      return false
    }

    switch (retryClass) {
      case RetryClass.Transport:
        return this.retry.retryNetworkErrors
      case RetryClass.Status:
        return true
      case RetryClass.None:
      default:
        return false
    }
  }

  private getCached(key: string): ExchangeResponse | undefined {
    if (!this.cache.enabled) {
      return undefined
    }

    const entry = this.cacheEntries.get(key)
    if (!entry) {
      return undefined
    }

    if (entry.expiresAtMs <= Date.now()) {
      this.cacheEntries.delete(key)
      return undefined
    }

    return entry.response
  }

  private setCached(key: string, response: ExchangeResponse): void {
    if (!this.cache.enabled) {
      return
    }

    const ttlMs = response.expiresIn > 0 ? response.expiresIn * 1000 : this.cache.defaultTtlMs
    if (ttlMs <= 0) {
      return
    }

    this.cacheEntries.set(key, {
      response,
      expiresAtMs: Date.now() + ttlMs,
    })
  }

  private incTotal(result: 'success' | 'cached' | 'error' | 'unauthorized'): void {
    this.metrics.incTotal?.(result)
  }

  private observeDuration(durationMs: number): void {
    this.metrics.observeDuration?.(durationMs)
  }

  private async sleepWithSignal(durationMs: number, signal?: AbortSignal): Promise<boolean> {
    if (durationMs <= 0) {
      return true
    }

    if (signal?.aborted) {
      return false
    }

    return await new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        if (signal) {
          signal.removeEventListener('abort', onAbort)
        }
        resolve(true)
      }, durationMs)

      const onAbort = () => {
        clearTimeout(timer)
        resolve(false)
      }

      if (signal) {
        signal.addEventListener('abort', onAbort, { once: true })
      }
    })
  }
}

export class ExchangeCallBuilder {
  private readonly request: ExchangeRequest = {}
  private timeoutMs?: number
  private signal?: AbortSignal

  constructor(private readonly client: PassportExchangeClient, private readonly sourceToken: string) {}

  organizationId(organizationId: string): this {
    this.request.organizationId = organizationId
    return this
  }

  projectId(projectId: string): this {
    this.request.projectId = projectId
    return this
  }

  timeout(timeoutMs: number): this {
    this.timeoutMs = timeoutMs
    return this
  }

  withSignal(signal: AbortSignal): this {
    this.signal = signal
    return this
  }

  async send(): Promise<ExchangeResponse> {
    return await this.client.exchangeWithRequest(this.sourceToken, this.request, this.timeoutMs, this.signal)
  }
}

function createAbortSignal(signal?: AbortSignal, timeoutMs?: number): { signal?: AbortSignal; cleanup: () => void } {
  if (!signal && (!timeoutMs || timeoutMs <= 0)) {
    return { signal: undefined, cleanup: () => undefined }
  }

  const controller = new AbortController()
  let timeoutId: NodeJS.Timeout | undefined

  const onAbort = () => controller.abort()
  if (signal) {
    signal.addEventListener('abort', onAbort, { once: true })
  }

  if (timeoutMs && timeoutMs > 0) {
    timeoutId = setTimeout(() => controller.abort(), timeoutMs)
  }

  return {
    signal: controller.signal,
    cleanup: () => {
      if (timeoutId) {
        clearTimeout(timeoutId)
      }
      if (signal) {
        signal.removeEventListener('abort', onAbort)
      }
    },
  }
}

async function parseOAuthError(response: Response): Promise<OAuthErrorPayload> {
  try {
    return (await response.json()) as OAuthErrorPayload
  } catch {
    return {}
  }
}

function backoffDuration(minBackoffMs: number, maxBackoffMs: number): number {
  if (maxBackoffMs <= minBackoffMs) {
    return minBackoffMs
  }

  try {
    return randomInt(minBackoffMs, maxBackoffMs + 1)
  } catch {
    return minBackoffMs + Math.floor((maxBackoffMs - minBackoffMs) / 2)
  }
}

function exchangeCacheKey(sourceToken: string, request: ExchangeRequest): string {
  const hash = createHash('sha256')
  hash.update(sourceToken)
  hash.update('|')
  hash.update(request.organizationId ?? '')
  hash.update('|')
  hash.update(request.projectId ?? '')
  return hash.digest('hex')
}
