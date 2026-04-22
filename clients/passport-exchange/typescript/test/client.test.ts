import { describe, expect, it } from 'vitest'

import {
  EditExchangeRequestError,
  HttpStatusError,
  PassportExchangeClient,
  SourceTokenRequiredError,
  UnauthorizedError,
} from '../src/index.js'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  })
}

describe('PassportExchangeClient', () => {
  it('exchanges token successfully', async () => {
    let called = 0
    const client = new PassportExchangeClient({
      baseUrl: 'https://identity.example.com',
      fetchImpl: async (_url, init) => {
        called += 1
        expect(init?.method).toBe('POST')
        const body = String(init?.body)
        expect(body).toContain('organizationId=org-1')
        expect(body).toContain('projectId=project-1')

        return jsonResponse(200, { passport: 'passport-jwt', expires_in: 120 })
      },
    })

    const response = await client
      .exchange('source-token')
      .organizationId('org-1')
      .projectId('project-1')
      .send()

    expect(response.passport).toBe('passport-jwt')
    expect(response.expiresIn).toBe(120)
    expect(response.cached).toBe(false)
    expect(called).toBe(1)
  })

  it('returns cache hit on second call', async () => {
    let called = 0
    const client = new PassportExchangeClient({
      baseUrl: 'https://identity.example.com',
      cache: { enabled: true },
      fetchImpl: async () => {
        called += 1
        return jsonResponse(200, { passport: 'cached-passport', expires_in: 60 })
      },
    })

    const first = await client.exchange('source-token').send()
    const second = await client.exchange('source-token').send()

    expect(first.cached).toBe(false)
    expect(second.cached).toBe(true)
    expect(called).toBe(1)
  })

  it('surfaces unauthorized', async () => {
    const client = new PassportExchangeClient({
      baseUrl: 'https://identity.example.com',
      fetchImpl: async () => jsonResponse(401, { error: 'access_denied', error_description: 'token invalid' }),
    })

    await expect(client.exchange('source-token').send()).rejects.toBeInstanceOf(UnauthorizedError)
  })

  it('does not retry 400', async () => {
    let called = 0
    const client = new PassportExchangeClient({
      baseUrl: 'https://identity.example.com',
      fetchImpl: async () => {
        called += 1
        return jsonResponse(400, { error: 'invalid_request', error_description: 'bad request' })
      },
    })

    await expect(client.exchange('source-token').send()).rejects.toBeInstanceOf(HttpStatusError)
    expect(called).toBe(1)
  })

  it('retries 503 by default', async () => {
    let called = 0
    const client = new PassportExchangeClient({
      baseUrl: 'https://identity.example.com',
      fetchImpl: async () => {
        called += 1
        if (called === 1) {
          return jsonResponse(503, { error: 'server_error', error_description: 'temporary' })
        }

        return jsonResponse(200, { passport: 'retried-passport', expires_in: 60 })
      },
    })

    const response = await client.exchange('source-token').send()
    expect(response.passport).toBe('retried-passport')
    expect(called).toBe(2)
  })

  it('does not retry 500 by default', async () => {
    let called = 0
    const client = new PassportExchangeClient({
      baseUrl: 'https://identity.example.com',
      fetchImpl: async () => {
        called += 1
        return jsonResponse(500, { error: 'server_error', error_description: 'unknown' })
      },
    })

    await expect(client.exchange('source-token').send()).rejects.toBeInstanceOf(HttpStatusError)
    expect(called).toBe(1)
  })

  it('can retry 500 when configured', async () => {
    let called = 0
    const client = new PassportExchangeClient({
      baseUrl: 'https://identity.example.com',
      retry: {
        retryableStatusCodes: [500, 503],
      },
      fetchImpl: async () => {
        called += 1
        if (called === 1) {
          return jsonResponse(500, { error: 'server_error', error_description: 'configured retry' })
        }
        return jsonResponse(200, { passport: 'configured-retry-passport', expires_in: 60 })
      },
    })

    const response = await client.exchange('source-token').send()
    expect(response.passport).toBe('configured-retry-passport')
    expect(called).toBe(2)
  })

  it('uses request timeout on builder', async () => {
    const client = new PassportExchangeClient({
      baseUrl: 'https://identity.example.com',
      retry: { retryNetworkErrors: false },
      fetchImpl: async (_url, init) => {
        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => resolve(), 80)
          init?.signal?.addEventListener('abort', () => {
            clearTimeout(timer)
            reject(new DOMException('aborted', 'AbortError'))
          })
        })

        return jsonResponse(200, { passport: 'slow-passport', expires_in: 60 })
      },
    })

    await expect(client.exchange('source-token').timeout(10).send()).rejects.toBeInstanceOf(DOMException)
  })

  it('does not retry request editor errors', async () => {
    let editorCalls = 0
    const client = new PassportExchangeClient({
      baseUrl: 'https://identity.example.com',
      requestEditors: [
        () => {
          editorCalls += 1
          throw new Error('editor failure')
        },
      ],
    })

    await expect(client.exchange('source-token').send()).rejects.toBeInstanceOf(EditExchangeRequestError)
    expect(editorCalls).toBe(1)
  })

  it('rejects empty source token', async () => {
    const client = new PassportExchangeClient({ baseUrl: 'https://identity.example.com' })
    await expect(client.exchange(' ').send()).rejects.toBeInstanceOf(SourceTokenRequiredError)
  })
})
