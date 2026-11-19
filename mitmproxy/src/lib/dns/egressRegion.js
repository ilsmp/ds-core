const http = require('node:http')
const https = require('node:https')
const log = require('../../utils/util.log.server')

// 直连出口地域探测(不经过本代理, 测的是本机真实出口)。
// 地域敏感家族(如 google 的 AI 模式资格判定)按出口地域决定是否走中继池:
// 受限地域 => 中继; 非受限 => 官方/远程预设直连, 不一刀切(2026-11-19)。
const cache = { region: null, ts: 0, inflight: null }
const DEFAULT_PROBES = ['https://ipapi.co/json/', 'https://freeipapi.com/api/json/', 'http://ip-api.com/json']

function fetchJson (url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https:') ? https : http
    const req = mod.get(url, { timeout: timeoutMs, headers: { 'user-agent': 'dev-sidecar-region-probe/1.0' } }, (res) => {
      let buf = ''
      res.on('data', (c) => { buf += c })
      res.on('end', () => {
        try {
          resolve(JSON.parse(buf))
        } catch (e) {
          reject(e)
        }
      })
    })
    req.on('timeout', () => req.destroy(new Error('probe timeout')))
    req.on('error', reject)
  })
}

function extractRegion (j) {
  if (!j || typeof j !== 'object') return null
  const v = j.country_code || j.countryCode || j.country || j.iso2
  if (typeof v === 'string' && v.length === 2) return v.toUpperCase()
  return null
}

async function detect (policy) {
  const probes = policy && Array.isArray(policy.probes) && policy.probes.length ? policy.probes : DEFAULT_PROBES
  for (const url of probes) {
    try {
      const region = extractRegion(await fetchJson(url, (policy && policy.probeTimeoutMs) || 4000))
      if (region) return region
    } catch {
      // 换下一个探测源
    }
  }
  return null
}

/**
 * 直连出口是否处于受限地域。缓存 TTL 默认 30 分钟; 探测全部失败(未知)
 * 时按 policy.defaultRestricted(默认 true, 保守走中继)处理。
 */
async function isRestricted (policy, logRef) {
  const p = policy || {}
  const ttl = p.ttlMs || 30 * 60 * 1000
  const now = Date.now()
  const restrictedRegions = Array.isArray(p.restrictedRegions) && p.restrictedRegions.length ? p.restrictedRegions : ['CN']
  if (cache.region !== null && now - cache.ts < ttl) {
    return restrictedRegions.includes(cache.region)
  }
  // 探测全失败后的短缓存: 避免探测源宕机时每个请求都重新探测
  // (最坏开销封顶为 每60秒 一轮探针超时, 而非每请求)
  if (cache.region === null && cache.failedTs && now - cache.failedTs < (p.failTtlMs || 60000)) {
    return p.defaultRestricted !== false
  }
  if (!cache.inflight) {
    cache.inflight = detect(p).then((region) => {
      cache.inflight = null
      cache.region = region
      cache.ts = Date.now()
      ;(logRef || log).info(`[egress-region] 直连出口地域探测: ${region || '未知(按默认策略)'}`)
      return region
    })
  }
  const region = await cache.inflight
  if (region === null) {
    cache.failedTs = Date.now()
  }
  if (region === null) return p.defaultRestricted !== false
  return restrictedRegions.includes(region)
}

module.exports = { isRestricted, _cache: cache }
