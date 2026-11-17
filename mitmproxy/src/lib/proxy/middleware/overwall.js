const { Buffer } = require('node:buffer')
const fs = require('node:fs')
const path = require('node:path')
const URL = require('node:url')
const request = require('request')
const log = require('../../../utils/util.log.server')
const matchUtil = require('../../../utils/util.match')
const pac = require('./source/pac')
const deathRegistry = require('./overwall-death-registry')
const ProxyHttpAgent = require('../common/ProxyHttpAgent')
const { restoreVerifySslAgent } = require('../../interceptor/impl/req/interceptorUtil')
const dateUtil = require('@blue-frontier/dev-sidecar/src/utils/util.date')
const { resolvedSnapshot } = require('@blue-frontier/dev-sidecar/src/utils/util.secret-vault')

let pacClient = null

// 视为「转发目标连不上」的错误：只有这类错误才触发死亡标记 + 直连回退；
// HTTP 4xx/5xx 说明目标活着（拒绝服务≠服务死了），不降级。
const CONNECT_FAIL_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'ETIMEOUT',
  'EPIPE',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EAI_AGAIN',
  'UND_ERR_CONNECT_TIMEOUT',
  'ERR_SOCKET_CONNECTION_TIMEOUT',
])
// 转发目标(本地适配器)返回的「网关类」状态码：目标进程活着，但它的上游(如用户的
// Clash/VPN)不可用。与连接失败同等对待——标记死亡退避 + 本笔请求回退直连重试，
// 否则适配器上游挂掉期间增强域名会持续拿到 502，而官方默认直连路径本可以正常访问。
const GATEWAY_FAIL_STATUS = new Set([502, 503, 504])
function isConnectFailure (e) {
  if (!e)
    return false
  if (e.code && CONNECT_FAIL_CODES.has(e.code))
    return true
  if (!e.code && /连接超时|connect\\b.*time|socket.*time/i.test(String(e.message || '')))
    return true
  return false
}

function matchTarget (hostname, overWallTargetMap) {
  // 匹配配置文件
  const ret1 = matchUtil.matchHostname(overWallTargetMap, hostname, 'matched overwall')
  if (ret1) {
    if (ret1 === false || ret1 === 'false') {
      log.debug(`域名 ${hostname} 的overwall配置为 false，跳过增强功能，即使它在 pac.txt 里`)
      return null
    }
    return { source: 'config', value: ret1 }
  }

  // 匹配 pac.txt
  if (pacClient == null) {
    return null
  }
  const ret = pacClient.FindProxyForURL(`https://${hostname}`, hostname)
  if (ret && ret.indexOf('PROXY ') === 0) {
    log.info(`matchHostname: matched overwall: '${hostname}' -> '${ret}' in pac.txt`)
    return { source: 'pac' }
  } else {
    log.debug(`matchHostname: matched overwall: Not-Matched '${hostname}' -> '${ret}' in pac.txt`)
    return null
  }
}

function getUserBasePath () {
  const userHome = process.env.USERPROFILE || process.env.HOME || '/'
  return path.resolve(userHome, './.dev-sidecar')
}

// 下载的 pac.txt 文件保存路径
function getTmpPacFilePath () {
  return path.join(getUserBasePath(), '/pac.txt')
}

function loadPacLastModifiedTime (pacTxt) {
  const matched = pacTxt.match(/(?<=! Last Modified: )[^\r\n]+/g)
  if (matched && matched.length > 0) {
    try {
      return new Date(matched[0])
    } catch {
      return null
    }
  }
}

// 保存 pac 内容到 `~/pac.txt` 文件中
function savePacFile (pacTxt) {
  const pacFilePath = getTmpPacFilePath()
  try {
    fs.writeFileSync(pacFilePath, pacTxt)
    log.info('保存 pac.txt 文件成功:', pacFilePath)
  } catch (e) {
    log.error('保存 pac.txt 文件失败:', pacFilePath, ', error:', e)
    return
  }

  // 尝试解析和修改 pac.txt 文件时间
  const lastModifiedTime = loadPacLastModifiedTime(pacTxt)
  if (lastModifiedTime) {
    fs.stat(pacFilePath, (err, _stats) => {
      if (err) {
        log.error('修改 pac.txt 文件时间失败:', err)
        return
      }

      // 修改文件的访问时间和修改时间为当前时间
      fs.utimes(pacFilePath, lastModifiedTime, lastModifiedTime, (utimesErr) => {
        if (utimesErr) {
          log.error('修改 pac.txt 文件时间失败:', utimesErr)
        } else {
          log.info(`'${pacFilePath}' 文件的修改时间已更新为其最近更新时间 '${dateUtil.format(lastModifiedTime, false)}'`)
        }
      })
    })
  }
}

// 异步下载 pac.txt ，避免影响代理服务的启动速度
async function downloadPacAsync (pacConfig) {
  const remotePacFileUrl = pacConfig.pacFileUpdateUrl
  log.info('开始下载远程 pac.txt 文件:', remotePacFileUrl)
  request(remotePacFileUrl, (error, response, body) => {
    if (error) {
      log.error(`下载远程 pac.txt 文件失败: ${remotePacFileUrl}, error:`, error, ', response:', response, ', body:', body)
      return
    }
    if (response && response.statusCode === 200) {
      if (body == null || body.length < 100) {
        log.warn('下载远程 pac.txt 文件成功，但内容为空或内容太短，判断为无效的 pax.txt 文件:', remotePacFileUrl, ', body:', body)
        return
      } else {
        log.info('下载远程 pac.txt 文件成功:', remotePacFileUrl)
      }

      // 尝试解析Base64（注：https://gitlab.com/gfwlist/gfwlist/raw/master/gfwlist.txt 下载下来的是Base64格式）
      let pacTxt = body
      if (!pacTxt.includes('!---------------------EOF')) {
        try {
          pacTxt = Buffer.from(pacTxt, 'base64').toString('utf8')
          // log.debug('解析 base64 后的 pax:', pacTxt)
        } catch {
          log.error(`远程 pac.txt 文件内容即不是base64格式，也不是要求的格式，url: ${remotePacFileUrl}，body: ${body}`)
          return
        }
      }

      // 保存到本地
      savePacFile(pacTxt)
    } else {
      log.error(`下载远程 pac.txt 文件失败: ${remotePacFileUrl}, response:`, response, ', body:', body)
    }
  })
}

function buildServerList (overWallConfig) {
  const list = []
  const customServer = overWallConfig.server || {}
  const defaultServer = overWallConfig.serverDefault || {}
  // 口令优先取系统密钥库快照（fork 时以环境变量注入），配置里只留空串
  const storedPasswords = resolvedSnapshot().overwall || {}
  const passwordOf = (domain, cfg) => storedPasswords[domain] || (cfg && cfg.password)

  // 内置默认服务器 ID 固定为 0；用户自定义服务器在此基础上依次增加
  let nextId = 1
  for (const [domain, cfg] of Object.entries(defaultServer)) {
    if (!customServer[domain]) {
      list.push({
        id: cfg && cfg.id != null ? Number.parseInt(cfg.id, 10) : 0,
        domain,
        port: cfg && cfg.port,
        path: cfg && cfg.path,
        password: passwordOf(domain, cfg),
      })
    }
  }

  for (const [domain, cfg] of Object.entries(customServer)) {
    const item = {
      id: cfg && cfg.id != null ? Number.parseInt(cfg.id, 10) : nextId,
      domain,
      port: cfg && cfg.port,
      path: cfg && cfg.path,
      password: passwordOf(domain, cfg),
    }
    if (item.id >= nextId) {
      nextId = item.id + 1
    }
    list.push(item)
  }

  return list
}

function createOverwallMiddleware (overWallConfig) {
  if (!overWallConfig || overWallConfig.enabled !== true) {
    return null
  }
  if (overWallConfig.pac && overWallConfig.pac.enabled) {
    // 初始化pac
    pacClient = pac.createPacClient(overWallConfig.pac.pacFileAbsolutePath)
  }

  const serverList = buildServerList(overWallConfig)
  if (serverList.length === 0) {
    return null
  }
  const serverById = new Map(serverList.map(item => [item.id, item]))

  // 默认优先使用 ID 为 1 的服务器；若 ID 为 1 的服务器不存在，则自动使用 ID 为 0 的默认服务器
  const defaultServerId = serverById.has(1) ? 1 : 0

  function resolveServerId (targetValue) {
    if (targetValue && typeof targetValue === 'object' && targetValue.enabled !== false && targetValue.serverId != null) {
      const id = Number.parseInt(targetValue.serverId, 10)
      if (serverById.has(id)) {
        return id
      }
    }
    return defaultServerId
  }

  const overWallTargetMap = matchUtil.domainMapRegexply(overWallConfig.targets)
  // http 明文回环适配器专用 agent：原请求的 https agent 被复用时，
  // Node 会校验 agent 协议与请求协议一致，直接抛 ERR_INVALID_PROTOCOL。
  // 转发到 http:// 开头的 overwall 服务器（本地明文回环适配器）时必须换用它。
  let httpLoopbackAgent = null
  function getHttpLoopbackAgent () {
    if (httpLoopbackAgent == null) {
      httpLoopbackAgent = new ProxyHttpAgent()
    }
    return httpLoopbackAgent
  }

  // 改写后附加到 context.overwall 的结果回写器：
  // onSuccess → 目标存活，清除死亡标记回到官方转发路径；
  // onUpstreamError(e) → 连接类失败时标记死亡并恢复直连参数，返回是否已回退。
  function attachResultHook (context, rOptions, serverId, savedAgent, savedHeaders) {
    // 本笔请求是否已因转发失败回退直连: 回退后直连的成功不能误清死亡标记,
    // 否则每笔请求都会再撞一次死目标的连接超时, 退避机制失效。
    let fellBack = false
    const restoreDirect = () => {
      const saved = rOptions.original
      if (!saved)
        return
      rOptions.protocol = saved.protocol
      rOptions.hostname = saved.hostname
      rOptions.host = saved.host
      rOptions.path = saved.path
      if (saved.port != null)
        rOptions.port = saved.port
      if (saved.servername != null)
        rOptions.servername = saved.servername
      else delete rOptions.servername
      if (saved.verifyHost !== undefined)
        rOptions.verifyHost = saved.verifyHost
      else delete rOptions.verifyHost
      rOptions.headers = savedHeaders
      if (savedAgent !== undefined)
        rOptions.agent = savedAgent
      else delete rOptions.agent
    }
    context.overwall = {
      serverId,
      restore: restoreDirect,
      onSuccess: () => {
        if (fellBack) {
          // 直连回退的成功: 探测结果为「目标仍死」, 维持退避
          deathRegistry.markProbeResult(serverId, false)
          return
        }
        deathRegistry.markAlive(serverId)
      },
      onUpstreamStatus: (statusCode) => {
        if (!GATEWAY_FAIL_STATUS.has(Number(statusCode)))
          return false
        if (fellBack) {
          // 本笔已回退直连：直连源站自身的网关状态码不是适配器的锅，不能误标死亡
          return false
        }
        log.warn(`OverWall: 转发目标 serverId=${serverId} 返回 ${statusCode}（其上游不可用），标记死亡并回退直连`)
        deathRegistry.markDead(serverId)
        fellBack = true
        restoreDirect()
        return true
      },
      onUpstreamError: (e) => {
        if (!isConnectFailure(e))
          return false
        if (fellBack) {
          // 本笔已回退直连：直连自身的连接失败不应再次累计到适配器的退避上
          return false
        }
        deathRegistry.markDead(serverId)
        fellBack = true
        restoreDirect()
        return true
      },
    }
  }
  return {
    sslConnectInterceptor: (req, _cltSocket, _head) => {
      const hostname = req.url.split(':')[0]
      return matchTarget(hostname, overWallTargetMap) != null
    },
    // WebSocket（upgrade）路径的改写：与 requestIntercept 同一套服务器选择与回环改写，
    // 升级请求没有 res，因此不写 DS-Overwall 响应头。
    upgradeIntercept (context) {
      const { rOptions } = context
      if (rOptions.protocol === 'http:') {
        return
      }
      const hostname = rOptions.hostname
      const target = matchTarget(hostname, overWallTargetMap)
      if (target == null) {
        return
      }

      const serverId = target.source === 'config' ? resolveServerId(target.value) : defaultServerId
      const selected = serverById.get(serverId)
      if (!selected) {
        return
      }
      // 转发目标死亡窗口内：跳过改写，本笔请求走官方默认直连路径（SNI 伪装 + 预设 IP）
      if (deathRegistry.isDead(serverId)) {
        log.warn(`OverWall(upgrade): 转发目标 serverId=${serverId} 暂不可达，跳过增强改写走直连: ${hostname}`)
        return
      }

      const domain = selected.domain
      const port = selected.port
      const path = selected.path
      const password = selected.password
      const proxyTarget = `${domain}/${path}/${hostname}${rOptions.path}`

      const proxy = proxyTarget.indexOf('http:') === 0 || proxyTarget.indexOf('https:') === 0 ? proxyTarget : (`${rOptions.protocol}//${proxyTarget}`)
      const urlObj = URL.parse(proxy)

      const { agent: _agent, headers: _headers, ...original } = rOptions
      rOptions.original = original
      const savedAgent = rOptions.agent
      const savedHeaders = rOptions.headers ? { ...rOptions.headers } : rOptions.headers

      rOptions.protocol = urlObj.protocol
      rOptions.hostname = urlObj.hostname
      rOptions.host = urlObj.host
      if (rOptions.headers) {
        rOptions.headers.host = urlObj.host
        if (password) {
          rOptions.headers.dspassword = password
        }
      }
      rOptions.path = urlObj.path
      if (urlObj.port) {
        rOptions.port = Number.parseInt(urlObj.port)
      } else {
        rOptions.port = port || (rOptions.protocol === 'https:' ? 443 : 80)
      }

      // 目标是 overwall 服务器：丢弃原域名的 SNI 伪装与证书校验域名，
      // 并按目标协议换用明文回环 agent（与 requestIntercept 保持一致）。
      delete rOptions.servername
      delete rOptions.verifyHost
      restoreVerifySslAgent(rOptions)
      if (urlObj.protocol === 'http:') {
        rOptions.agent = getHttpLoopbackAgent()
      }

      log.info('OverWall(upgrade):', hostname, '➜', proxyTarget, `, serverId: ${serverId}`)
      attachResultHook(context, rOptions, serverId, savedAgent, savedHeaders)
      return true
    },
    requestIntercept (context, req, res, _ssl, _next) {
      const { rOptions, log } = context
      if (rOptions.protocol === 'http:') {
        return
      }
      const hostname = rOptions.hostname
      const target = matchTarget(hostname, overWallTargetMap)
      if (target == null) {
        return
      }

      const serverId = target.source === 'config' ? resolveServerId(target.value) : defaultServerId
      const selected = serverById.get(serverId)
      if (!selected) {
        return
      }
      // 转发目标死亡窗口内：跳过改写，本笔请求走官方默认直连路径（SNI 伪装 + 预设 IP）
      if (deathRegistry.isDead(serverId)) {
        log.warn(`OverWall: 转发目标 serverId=${serverId} 暂不可达，跳过增强改写走直连: ${hostname}`)
        return
      }

      const domain = selected.domain
      const port = selected.port
      const path = selected.path
      const password = selected.password
      const proxyTarget = `${domain}/${path}/${hostname}${req.url}`

      // const backup = interceptOpt.backup
      const proxy = proxyTarget.indexOf('http:') === 0 || proxyTarget.indexOf('https:') === 0 ? proxyTarget : (`${rOptions.protocol}//${proxyTarget}`)
      // eslint-disable-next-line node/no-deprecated-api
      const urlObj = URL.parse(proxy)

      // 备份原始请求参数，不包含 agent 和 headers（agent 是共享单例，headers 在代理转发时会被改写）
      const { agent: _agent, headers: _headers, ...original } = rOptions
      rOptions.original = original
      const savedAgent = rOptions.agent
      const savedHeaders = { ...rOptions.headers }

      rOptions.protocol = urlObj.protocol
      rOptions.hostname = urlObj.hostname
      rOptions.host = urlObj.host
      rOptions.headers.host = urlObj.host
      if (password) {
        rOptions.headers.dspassword = password
      }
      rOptions.path = urlObj.path
      if (urlObj.port) {
        rOptions.port = Number.parseInt(urlObj.port)
      } else {
        rOptions.port = port || (rOptions.protocol === 'https:' ? 443 : 80)
      }

      // 目标是 overwall 服务器：不能沿用原域名的 SNI 伪装与证书校验域名，
      // 否则 sni 拦截器先写下的 servername 会被带到 overwall 服务器的 TLS 握手上。
      // （sni 拦截器改为只改 rOptions 后，overwall 才会在它之后执行到）
      delete rOptions.servername
      delete rOptions.verifyHost
      // 同理，原域名规则里的 unVerifySsl 也不应作用到新目标上
      restoreVerifySslAgent(rOptions)
      // 目标协议为 http 时换 http agent（本地回环明文适配器场景）；
      // restoreVerifySslAgent 只处理 https 系 agent，http 目标必须显式换。
      if (urlObj.protocol === 'http:') {
        rOptions.agent = getHttpLoopbackAgent()
      }

      log.info('OverWall:', rOptions.hostname, '➜', proxyTarget, `, serverId: ${serverId}`)

      res.setHeader('DS-Overwall', `${target.source}:${serverId}`)
      attachResultHook(context, rOptions, serverId, savedAgent, savedHeaders)

      return true
    },
  }
}

module.exports = {
  getTmpPacFilePath,
  downloadPacAsync,
  createOverwallMiddleware,
  isConnectFailure,
}
