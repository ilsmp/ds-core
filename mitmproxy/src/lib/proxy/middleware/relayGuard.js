const matchUtil = require('../../../utils/util.match')
const ipBlacklist = require('../../speed/ipBlacklist')
const log = require('../../../utils/util.log.server')

// 中继守卫（2026-11-19）
//
// 背景：地域敏感家族（server.preSetIpListRelay 白名单，如 google 系）必须走「预设中继直连」，
// 出口地域才稳定。但这些域名同时存在于 gfwlist(pac.txt) 中，增强判定链里 pac 命中就会把请求
// 转发到本地适配器及其上游 VPN，出口地域随 VPN 节点漂移；漂到 CN 时 google AI 模式报
// 「您的设备或账号目前无法使用 AI 模式」，并且只在适配器死亡退避窗口内才恢复，表现为
// 难以定位的间歇性故障。
//
// 分层降级（与 DNS 层的中继预设池、持久化 IP 黑名单共用同一份健康信号）：
//   1) 中继 IP 健康            => 守卫生效，跳过增强，走中继直连（出口稳定）
//   2) 中继 IP 刚被拉黑(宽限期内) => 守卫仍生效；DNS 层已把该 IP 过滤掉，落回官方预设直连
//   3) 中继 IP 持续不可用(超宽限期) => 守卫放行，pac/targets 决定，进适配器兜底
//   4) 中继复测连续两次成功自动解禁 => 回到 1)
// targets 里的显式配置（true/false）优先级始终高于本守卫，使用者可为任一域名单独开关增强。

// 中继全部不可用后，等待多久才放行增强兜底：单次网络抖动不翻路径
const FALLBACK_GRACE_MS = 30 * 1000
// 同一域名放行日志的节流间隔，避免兜底期间每笔请求都刷一条 warn
const LOG_THROTTLE_MS = 60 * 1000

// 与 dns/base.js 的 mapToList 语义一致：真值即生效（true/非空字符串/对象），
// false / null / 0 / 'false' / '0' 视为未启用
function toIpList (value) {
  if (Array.isArray(value)) {
    return value.slice()
  }
  const list = []
  for (const key in value) {
    const v = value[key]
    if (v && v !== 'false' && v !== '0') {
      list.push(key)
    }
  }
  return list
}

/**
 * @param relayListMap 已编译的中继白名单（matchUtil.domainMapRegexply 的产物），空表返回 null
 * @param opts { graceMs?, isBlacklistedSince?, now?, logger? } —— 后三项供单测注入
 * @returns {((hostname: string) => boolean) | null} true = 跳过增强，走中继直连
 */
function createRelayGuard (relayListMap, opts = {}) {
  if (relayListMap == null) {
    return null
  }
  const hasEntry = Object.keys(relayListMap.origin || {}).length > 0
    || Object.keys(relayListMap).some(key => key !== 'origin')
  if (!hasEntry) {
    return null
  }
  const graceMs = opts.graceMs != null ? opts.graceMs : FALLBACK_GRACE_MS
  const blacklistedSince = opts.isBlacklistedSince || (ip => ipBlacklist.getSince(ip))
  const now = opts.now || (() => Date.now())
  const logger = opts.logger || log
  const lastLogAt = new Map()

  return (hostname) => {
    const matched = matchUtil.matchHostname(relayListMap, hostname, 'matched preSetIpListRelay(overwall-guard)')
    if (matched == null || matched === false || matched === 'false') {
      return false // 不属于中继白名单家族，增强判定照旧
    }
    const ipList = toIpList(matched)
    if (ipList.length === 0) {
      return false // 白名单键被显式停用，等同于未配置中继
    }
    const ts = now()
    // 宽限期内的拉黑视为「抖动」，继续按中继家族处理（此时 DNS 层已落回官方预设直连）
    const usable = ipList.filter((ip) => {
      const since = blacklistedSince(ip)
      return since == null || (ts - since) < graceMs
    })
    if (usable.length > 0) {
      return true
    }
    const last = lastLogAt.get(hostname) || 0
    if (ts - last >= LOG_THROTTLE_MS) {
      lastLogAt.set(hostname, ts)
      logger.warn(`[overwall-guard] ${hostname} 的中继预设 IP 持续不可用(${ipList.join(', ')})，本次放行增强/适配器兜底；中继复测恢复后自动回到中继直连`)
    }
    return false
  }
}

module.exports = { createRelayGuard, toIpList, FALLBACK_GRACE_MS }
