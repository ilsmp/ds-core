/**
 * 增强功能转发目标的「死亡状态」注册表（进程内单例）。
 *
 * 背景：增强模式把命中域名的请求改写到转发目标（官方服务器 ow-prod.docmirror.top
 * 或本地明文回环适配器）。目标进程不在/网络不可达时，请求会在 CONNECT 阶段
 * 超时 7 秒才失败，期间增强域名全部不可用 —— 而这些域名（google/github 等）
 * 走官方默认模式的直连路径（SNI 伪装 + 预设 IP）本可以正常访问。
 *
 * 策略（保持官方转发为主路径，仅在目标确认死亡时降级）：
 *   - 转发目标发生连接类失败 → markDead：此后 DEAD_MS 内该目标的请求不再改写，
 *     直接走原直连路径；
 *   - 到期自动半开：下一笔请求重新尝试转发，成功则 markAlive 回到官方路径，
 *     仍失败则按退避再次标记；
 *   - 只统计「连不上」类错误；HTTP 4xx/5xx 表示目标活着，不触发降级。
 */

const DEAD_MS_BASE = 5 * 1000
const DEAD_MS_MAX = 60 * 1000

// key: serverId（overwall 服务器列表里的 id），value: { deadUntil, failStreak }
const deadMap = new Map()

function isDead (serverId) {
  const entry = deadMap.get(serverId)
  if (!entry) {
    return false
  }
  if (Date.now() >= entry.deadUntil) {
    // 半开窗口：到期即视为可用，允许一笔请求重新探测转发目标
    deadMap.delete(serverId)
    return false
  }
  return true
}

function markDead (serverId) {
  const prev = deadMap.get(serverId)
  const failStreak = prev ? Math.min(prev.failStreak + 1, 6) : 1
  // 指数退避：5s → 10s → 20s → 40s → 60s（封顶），避免每笔请求都白等一次超时
  const backoff = Math.min(DEAD_MS_BASE * 2 ** (failStreak - 1), DEAD_MS_MAX)
  deadMap.set(serverId, { deadUntil: Date.now() + backoff, failStreak })
}

function markAlive (serverId) {
  deadMap.delete(serverId)
}

/** 调试/日志用：当前处于死亡状态的目标列表 */
function snapshot () {
  const now = Date.now()
  const list = []
  for (const [serverId, entry] of deadMap.entries()) {
    list.push({ serverId, remainMs: entry.deadUntil - now, failStreak: entry.failStreak })
  }
  return list
}

module.exports = { isDead, markDead, markAlive, snapshot }
