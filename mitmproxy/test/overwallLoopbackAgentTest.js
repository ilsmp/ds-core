'use strict'
// 回归测试: overwall 转发到本地明文回环适配器(http://127.0.0.1)时必须换 http agent。
// 背景: 用户注册 http://127.0.0.1 适配器后, 中间件改写了 rOptions.protocol='http:'
// 但沿用了原域名的 https agent, Node 校验 agent 协议与请求协议一致,
// 直接抛 TypeError [ERR_INVALID_PROTOCOL] Protocol "http:" not supported. Expected "https:"。
const assert = require('node:assert')
const https = require('node:https')
const AgentBase = require('agentkeepalive').HttpsAgent
const ProxyHttpAgent = require('../src/lib/proxy/common/ProxyHttpAgent')
const { createOverwallMiddleware } = require('../src/lib/proxy/middleware/overwall')

// ---- 1) 复现机制: https agent + http 协议 → Node 原生拒绝 ----
{
  const rOptions = { protocol: 'http:', hostname: '127.0.0.1', port: 8470, agent: new AgentBase() }
  let threw = null
  try {
    https.request(rOptions, () => {})
  } catch (e) {
    threw = e
  }
  assert.ok(threw, 'https.request with http protocol + https agent must throw synchronously')
  assert.strictEqual(threw.code, 'ERR_INVALID_PROTOCOL', 'error code: ' + (threw && threw.code))
  console.log('PASS mechanism-reproduced (ERR_INVALID_PROTOCOL)')
}

// ---- 2) 中间件: http 回环目标 → 换 http agent; https 目标 → 不换 ----
const config = {
  enabled: true,
  server: {
    'http://127.0.0.1': { id: 1, type: 'path', port: 8470, path: 'sec123', password: 'pw456' },
  },
  serverDefault: {
    'ow-prod.docmirror.top': { id: 0, port: 443, path: 'X2dvX292ZXJfd2FsbF8', password: '' },
  },
  targets: { '*.google.com': true },
  pac: { enabled: false },
}
const mw = createOverwallMiddleware(config)
assert.ok(mw, 'middleware must be created')

function runIntercept (targetProtocol) {
  const httpsAgent = new AgentBase()
  const rOptions = {
    protocol: 'https:',
    hostname: 'www.google.com',
    host: 'www.google.com',
    port: 443,
    path: '/search?q=x',
    headers: { host: 'www.google.com' },
    agent: httpsAgent,
  }
  const res = { headers: {}, setHeader (k, v) { this.headers[k] = v } }
  const context = { rOptions, log: { info () {}, debug () {}, warn () {}, error () {} } }
  const ret = mw.requestIntercept(context, { url: '/search?q=x' }, res, false, () => {})
  return { ret, rOptions, httpsAgent, res }
}

{
  const { ret, rOptions, httpsAgent, res } = runIntercept()
  assert.strictEqual(ret, true, 'interceptor should claim the request')
  assert.strictEqual(rOptions.protocol, 'http:', 'protocol rewritten to http:')
  assert.strictEqual(rOptions.hostname, '127.0.0.1')
  assert.strictEqual(rOptions.port, 8470)
  assert.ok(rOptions.path.startsWith('/sec123/www.google.com/'), 'path contains secret prefix: ' + rOptions.path)
  assert.strictEqual(rOptions.headers.dspassword, 'pw456', 'dspassword header set')
  assert.ok(rOptions.agent instanceof ProxyHttpAgent, 'agent swapped to ProxyHttpAgent, got: ' + (rOptions.agent && rOptions.agent.constructor.name))
  assert.notStrictEqual(rOptions.agent, httpsAgent, 'original https agent must not be reused')
  assert.ok(res.headers['DS-Overwall'], 'DS-Overwall header set')
  console.log('PASS http-loopback agent swap + rewrite')
}

{
  // https 官方服务器场景: 不应换 http agent(仍走 https agent 链路)
  const configHttps = JSON.parse(JSON.stringify(config))
  delete configHttps.server['http://127.0.0.1']
  const mwHttps = createOverwallMiddleware(configHttps)
  const httpsAgent = new AgentBase()
  const rOptions = {
    protocol: 'https:', hostname: 'www.google.com', host: 'www.google.com', port: 443,
    path: '/', headers: { host: 'www.google.com' }, agent: httpsAgent,
  }
  const res = { setHeader () {} }
  const ret = mwHttps.requestIntercept({ rOptions, log: { info () {}, debug () {} } }, { url: '/' }, res, false, () => {})
  assert.strictEqual(ret, true)
  assert.strictEqual(rOptions.protocol, 'https:')
  assert.strictEqual(rOptions.agent, httpsAgent, 'https target keeps https agent')
  console.log('PASS https-target agent untouched')
}

// ---- 3) 非匹配域名不拦截 ----
{
  const rOptions = {
    protocol: 'https:', hostname: 'example.com', host: 'example.com', port: 443,
    path: '/', headers: { host: 'example.com' }, agent: new AgentBase(),
  }
  const ret = mw.requestIntercept({ rOptions, log: { info () {}, debug () {} } }, { url: '/' }, { setHeader () {} }, false, () => {})
  assert.notStrictEqual(ret, true, 'unmatched host must not be intercepted')
  console.log('PASS unmatched-host untouched')
}

console.log('ALL PASS')

