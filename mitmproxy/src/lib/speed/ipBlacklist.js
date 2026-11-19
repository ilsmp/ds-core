const fs = require('node:fs')
const path = require('node:path')
const log = require('../../utils/util.log.server')

// 持久化 IP 黑名单: 连接失败的预设 IP 跨重启拉黑, 默认 7 天过期,
// 迟滞恢复(连续两次成功)时自动解禁。官方远程更新新增的坏 IP 同样
// 被自动屏蔽, 无需冻结整份远程配置(2026-11-19)。
// 条目结构: { ts, reason, hostname, okStreak } —— hostname 供所属域名的
// 测速周期自动复测: 连续两次探测成功自动解禁, 7 天过期兜底, 不会永久拉黑。
const EXPIRE_MS = 7 * 24 * 60 * 60 * 1000
let filePath = null
let data = null

function file () {
  if (filePath) return filePath
  try {
    const { getUserBasePath } = require('@blue-frontier/dev-sidecar/src/config/index.js')
    filePath = path.join(getUserBasePath(false), 'ip-blacklist.json')
  } catch {
    filePath = path.join(process.env.DEV_SIDECAR_USER_BASE || path.join(process.env.HOME || '', '.dev-sidecar'), 'ip-blacklist.json')
  }
  return filePath
}

function load () {
  if (data) return data
  try {
    data = JSON.parse(fs.readFileSync(file(), 'utf8')) || {}
  } catch {
    data = {}
  }
  return data
}

function save () {
  try {
    fs.writeFileSync(file(), JSON.stringify(data, null, 2))
  } catch (e) {
    log.warn('[ip-blacklist] 写入失败(不影响运行):', e && e.message)
  }
}

module.exports = {
  isBlacklisted (ip) {
    const e = load()[ip]
    if (!e) return false
    if (Date.now() - e.ts > EXPIRE_MS) {
      delete load()[ip]
      save()
      return false
    }
    return true
  },
  // 拉黑起始时间戳（未拉黑或已过期返回 null）：供中继守卫的宽限期判断使用，
  // 避免单次抖动就把地域敏感家族翻到适配器出口（见 middleware/relayGuard）
  getSince (ip) {
    const e = load()[ip]
    if (!e) return null
    if (Date.now() - e.ts > EXPIRE_MS) {
      delete load()[ip]
      save()
      return null
    }
    return e.ts
  },
  add (ip, reason, hostname) {
    if (!ip) return
    const d = load()
    if (d[ip]) return
    d[ip] = { ts: Date.now(), reason: String(reason || 'failed').slice(0, 120), hostname: hostname || '', okStreak: 0 }
    log.warn(`[ip-blacklist] 拉黑 ${ip}: ${reason}`)
    save()
  },
  // 复测成功计数; 达阈返回 true 表示应解禁
  noteRecheck (ip, success) {
    const d = load()
    const e = d[ip]
    if (!e) return false
    e.okStreak = success ? (e.okStreak || 0) + 1 : 0
    if (success && e.okStreak >= 2) {
      delete d[ip]
      save()
      log.info(`[ip-blacklist] 复测连续两次成功, 解禁 ${ip}`)
      return true
    }
    save()
    return false
  },
  entriesForHostname (hostname) {
    const now = Date.now()
    return Object.entries(load()).filter(([ip, e]) => e.hostname === hostname && now - e.ts <= EXPIRE_MS).map(([ip]) => ip)
  },
  remove (ip) {
    const d = load()
    if (!d[ip]) return
    delete d[ip]
    log.info(`[ip-blacklist] 解禁 ${ip} (迟滞恢复达标)`)
    save()
  },
  _expireMs: EXPIRE_MS,
}
