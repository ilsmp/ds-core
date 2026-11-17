const http = require('node:http')
const https = require('node:https')
const net = require('node:net')
const log = require('../../../utils/util.log.server')
const util = require('../common/util')
const DnsUtil = require('../../dns')
const dnsLookup = require('./dnsLookup')
const { applyTlsVerifyPolicy } = require('./tlsVerify')

// copy from node-http-proxy.  ^_^

// create upgradeHandler function
// serverSetting: server config (verifySsl etc.)
// externalProxy: external proxy (string or function(req, ssl) => string), 与 createRequestHandler 一致
// dnsConfig: 完整 DNS 配置（mapping/preSetIpList/providers/speedTest），用于升级路径的 DNS 优选
// createIntercepts: 拦截器工厂（context => interceptors[]），把 sni/verifyHost 等规则应用到升级路径
// middlewares: 插件中间件（如 overwall），升级路径与常规请求路径共用同一改写逻辑：
// 命中增强目标时改写 clientOptions 指向适配器/服务器（与 requestIntercept 保持一致），
// 否则 ws/wss 升级会绕过增强功能，用被污染的默认 DNS 直连目标导致连接被重置。
// 升级（WebSocket）请求不走常规 requestHandler，必须把 SNI 伪装 + DNS 优选补齐，
// 否则 intercepted 域名的 wss:// 升级会因为无 SNI 或 DNS 未优选而失败。
module.exports = function createUpgradeHandler (serverSetting, externalProxy, dnsConfig, createIntercepts, middlewares = []) {
  return function upgradeHandler (req, cltSocket, head, ssl) {
    let overwallHook = null

    // 从原始请求构建上游请求参数：拦截器（sni/verifyHost 等）→ overwall 改写（可能指向
    // 适配器/官方服务器）→ 证书策略 → DNS 优选。直连回退重试时重新调用，确保
    // SNI/DNS/证书策略按「还原后的原域名」而不是「改写后的目标」重新套用。
    function prepareOptions () {
      const options = util.getOptionsFromRequest(req, ssl, externalProxy, serverSetting)
      // WebSocket 升级请求必须保留 Upgrade/Connection 头：
      // getOptionsFromRequest 是为普通请求设计的，会把 Connection 改写成 keep-alive，
      // 上游收不到 Upgrade 头就不会返回 101，升级路径直接失败。
      // 改写为回环适配器请求后 Connection 头会在适配器侧按 hop-by-hop 规则剥离。
      if (req.headers && String(req.headers.upgrade || '').toLowerCase() === 'websocket') {
        options.headers = options.headers || {}
        options.headers.connection = req.headers.connection || 'Upgrade'
        options.headers.upgrade = req.headers.upgrade
      }
      if (ssl && options.hostname && !options.servername) {
        // TLS 握手需要带 SNI（与 createRequestHandler 的常规请求路径保持一致）；
        // 缺失 SNI 时上游会报 WRONG_VERSION_NUMBER 或证书不匹配，
        // 这正是此前 wss:// 升级失败的根因（server.log 中的 upgradeHandler error）。
        options.servername = options.hostname
      }

      // 应用拦截器（sni/verifyHost/proxy 等）到升级路径
      if (createIntercepts) {
        try {
          const context = {
            rOptions: options,
            log,
            setting: serverSetting,
          }
          const interceptors = createIntercepts(context)
          if (interceptors && interceptors.length > 0) {
            // 升级请求没有真正的 res；给一个吸收 setHeader 的 stub，
            // 避免 sni/proxy 等拦截器在 res.setHeader 上报错。
            const noopRes = { setHeader: () => {}, getHeader: () => undefined, getHeaders: () => ({}) }
            for (const interceptor of interceptors) {
              if (interceptor && interceptor.requestIntercept) {
                // 包装后的拦截器签名是 (context, req, res, ssl, next)，interceptOpt/matched 由闭包提供
                interceptor.requestIntercept(context, req, noopRes, ssl, () => {})
              }
            }
          }
        } catch (e) {
          log.error('upgradeHandler intercept error:', e)
        }
      }

      // 插件中间件（overwall 等）最后执行，与 createRequestHandler 的执行顺序保持一致：
      // 命中增强目标的升级请求在此被改写为指向适配器/服务器的明文回环请求。
      if (Array.isArray(middlewares)) {
        const ctx = { rOptions: options, log, setting: serverSetting }
        for (const middleware of middlewares) {
          if (middleware && typeof middleware.upgradeIntercept === 'function') {
            try {
              middleware.upgradeIntercept(ctx)
            } catch (e) {
              log.error('upgradeHandler middleware error:', e)
            }
          }
        }
        overwallHook = ctx.overwall || null
      }

      // 证书校验：与常规请求路径共用同一套策略（默认真实域名 / verifyHost 覆盖 / 显式 unVerifySsl）
      applyTlsVerifyPolicy(options, log)

      // DNS 优选：intercepted 域名的自定义 DNS 映射同样作用于升级路径
      if (options.hostname && dnsConfig && dnsConfig.dnsMap && !net.isIP(options.hostname)) {
        // hostname 是纯域名（非 IP），需要 DNS 解析
        const isDnsIntercept = {}
        const dnsAndFamily = DnsUtil.getDNSAndFamily(dnsConfig, options.hostname)
        if (dnsAndFamily) {
          const fallbackDnsList = DnsUtil.getFallbackDnsList(dnsConfig, dnsAndFamily.dns)
          options.lookup = dnsLookup.createLookupFunc(null, dnsAndFamily, 'upgrade', `upgrade ${options.hostname}:${options.port}`, options.port, isDnsIntercept, { fallbackDnsList })
          if (dnsAndFamily.family === 6) {
            options.family = 6
          }
        } else {
          options.lookup = dnsLookup.createDefaultLookupFunc(null, 'upgrade', `${options.hostname}:${options.port}`, DnsUtil.getFallbackDnsList(dnsConfig, null))
        }
      }
      return options
    }

    const clientOptions = prepareOptions()

    // 把升级请求双向接通（101 响应头 + socket pipe）。首次转发与直连回退重试共用。
    // outerHandlesError=true: 错误处理交给外层（sendWithFallback 的回退逻辑），
    // 内部只记日志，不再重复给客户端写 502（否则回退重试时客户端会先收到一个多余的 502）。
    function attachUpgradeRelay (proxyReqRef, onUpgradeSuccess, outerHandlesError = false) {
      proxyReqRef.on('error', (e) => {
        log.error('upgradeHandler error:', e)
        if (outerHandlesError)
          return
        if (!cltSocket.destroyed) {
          cltSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
        }
      })
      proxyReqRef.on('response', (res) => {
        // 上游没有回 101 而是普通 HTTP 响应：把状态行+响应头透传给客户端，再关闭
        if (!res.upgrade) {
          // 网关类状态码(适配器活着但其上游不可用)：标记死亡退避，后续升级请求走直连
          if (overwallHook && typeof overwallHook.onUpstreamStatus === 'function' && overwallHook.onUpstreamStatus(res.statusCode)) {
            log.warn('upgradeHandler: 转发目标返回 ' + res.statusCode + '，已标记死亡，后续走直连')
          }
          const lines = [`HTTP/1.1 ${res.statusCode || 502} ${res.statusMessage || 'Bad Gateway'}`]
          for (const key of Object.keys(res.headers)) {
            const value = res.headers[key]
            if (Array.isArray(value)) {
              for (const v of value) lines.push(`${key}: ${v}`)
            } else {
              lines.push(`${key}: ${value}`)
            }
          }
          cltSocket.write(`${lines.join('\r\n')}\r\n\r\n`)
          res.pipe(cltSocket)
        }
      })
      proxyReqRef.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
        if (onUpgradeSuccess)
          onUpgradeSuccess()
        proxySocket.on('error', (e) => {
          log.error('upgrade error:', e)
        })
        cltSocket.on('error', (e) => {
          log.error('upgrade socket error:', e)
          proxySocket.end()
        })
        proxySocket.setTimeout(0)
        proxySocket.setNoDelay(true)
        proxySocket.setKeepAlive(true, 0)
        if (proxyHead && proxyHead.length) {
          proxySocket.unshift(proxyHead)
        }
        const responseLines = [`HTTP/1.1 ${proxyRes.statusCode || 101} ${proxyRes.statusMessage || 'Switching Protocols'}`]
        for (const key of Object.keys(proxyRes.headers)) {
          const value = proxyRes.headers[key]
          if (Array.isArray(value)) {
            for (const v of value) responseLines.push(`${key}: ${v}`)
          } else {
            responseLines.push(`${key}: ${value}`)
          }
        }
        cltSocket.write(`${responseLines.join('\r\n')}\r\n\r\n`)
        proxySocket.pipe(cltSocket).pipe(proxySocket)
      })
    }
    // WebSocket 升级请求必须保留 Upgrade/Connection 头：
    // getOptionsFromRequest 是为普通请求设计的，会把 Connection 改写成 keep-alive，
    // 上游收不到 Upgrade 头就不会返回 101，升级路径直接失败。
    // 改写为回环适配器请求后 Connection 头会在适配器侧按 hop-by-hop 规则剥离。
    if (req.headers && String(req.headers.upgrade || '').toLowerCase() === 'websocket') {
      clientOptions.headers = clientOptions.headers || {}
      clientOptions.headers.connection = req.headers.connection || 'Upgrade'
      clientOptions.headers.upgrade = req.headers.upgrade
    }
    // IP 目标不能设 SNI（Node 直接抛 ERR_INVALID_ARG_VALUE）：
    // overwall 改写后目标可能是适配器/服务器 IP，且改写时已显式 delete servername，
    // 不能在此回填成 IP。普通 wss 域名目标仍缺省回填真实域名。
    if (ssl && clientOptions.hostname && !clientOptions.servername && !net.isIP(clientOptions.hostname)) {
      // TLS 握手需要带 SNI（与 createRequestHandler 的常规请求路径保持一致）；
      // 缺失 SNI 时上游会报 WRONG_VERSION_NUMBER 或证书不匹配，
      // 这正是此前 wss:// 升级失败的根因（server.log 中的 upgradeHandler error）。
      clientOptions.servername = clientOptions.hostname
    }

    // 应用拦截器（sni/verifyHost/proxy 等）到升级路径
    if (createIntercepts) {
      try {
        const context = {
          rOptions: clientOptions,
          log,
          setting: serverSetting,
        }
        const interceptors = createIntercepts(context)
        if (interceptors && interceptors.length > 0) {
          // 升级请求没有真正的 res；给一个吸收 setHeader 的 stub，
          // 避免 sni/proxy 等拦截器在 res.setHeader 上报错。
          const noopRes = { setHeader: () => {}, getHeader: () => undefined, getHeaders: () => ({}) }
          for (const interceptor of interceptors) {
            if (interceptor && interceptor.requestIntercept) {
              // 包装后的拦截器签名是 (context, req, res, ssl, next)，interceptOpt/matched 由闭包提供
              interceptor.requestIntercept(context, req, noopRes, ssl, () => {})
            }
          }
        }
      } catch (e) {
        log.error('upgradeHandler intercept error:', e)
      }
    }

    // 插件中间件（overwall 等）最后执行，与 createRequestHandler 的执行顺序保持一致：
    // 命中增强目标的升级请求在此被改写为指向适配器/服务器的明文回环请求。
    if (Array.isArray(middlewares)) {
      const context = {
        rOptions: clientOptions,
        log,
        setting: serverSetting,
      }
      for (const middleware of middlewares) {
        if (middleware && typeof middleware.upgradeIntercept === 'function') {
          try {
            middleware.upgradeIntercept(context)
          } catch (e) {
            log.error('upgradeHandler middleware error:', e)
          }
        }
      }
    }

    // 证书校验：与常规请求路径共用同一套策略（默认真实域名 / verifyHost 覆盖 / 显式 unVerifySsl）
    applyTlsVerifyPolicy(clientOptions, log)

    // DNS 优选：intercepted 域名的自定义 DNS 映射同样作用于升级路径
    if (clientOptions.hostname && dnsConfig && dnsConfig.dnsMap && !net.isIP(clientOptions.hostname)) {
      // hostname 是纯域名（非 IP），需要 DNS 解析
      const isDnsIntercept = {}
      const dnsAndFamily = DnsUtil.getDNSAndFamily(dnsConfig, clientOptions.hostname)
      if (dnsAndFamily) {
        const fallbackDnsList = DnsUtil.getFallbackDnsList(dnsConfig, dnsAndFamily.dns)
        clientOptions.lookup = dnsLookup.createLookupFunc(null, dnsAndFamily, 'upgrade', `upgrade ${clientOptions.hostname}:${clientOptions.port}`, clientOptions.port, isDnsIntercept, { fallbackDnsList })
        if (dnsAndFamily.family === 6) {
          clientOptions.family = 6
        }
      } else {
        clientOptions.lookup = dnsLookup.createDefaultLookupFunc(null, 'upgrade', `${clientOptions.hostname}:${clientOptions.port}`, DnsUtil.getFallbackDnsList(dnsConfig, null))
      }
    }

    // 首次转发：增强目标的连接类失败 → 标记死亡 + 回退直连重试一次
    function sendWithFallback () {
      // 按改写后的协议选择模块：overwall 改写后 protocol 可能从 https: 变为 http:
      // （明文回环适配器），沿用入站 ssl 标志会触发 ERR_INVALID_PROTOCOL。
      const isUpstreamHttps = clientOptions.protocol === 'https:'
      const proxyReq = (isUpstreamHttps ? https : http).request(clientOptions)
      let retriedDirect = false
      proxyReq.on('error', (e) => {
        if (overwallHook && !retriedDirect && typeof overwallHook.onUpstreamError === 'function' && overwallHook.onUpstreamError(e)) {
          retriedDirect = true
          // prepareOptions() 会重新跑中间件：死亡窗口内跳过改写时 ctx.overwall 为空，
          // 闭包变量 overwallHook 被重置成 null，必须先把 hook 捕获出来再重建 options。
          const hook = overwallHook
          hook.restore()
          const retryOptions = prepareOptions()
          log.warn('upgradeHandler: 增强转发目标不可达，回退直连重试:', retryOptions.hostname)
          try {
            const retryReq = (retryOptions.protocol === 'https:' ? https : http).request(retryOptions)
            attachUpgradeRelay(retryReq, hook.onSuccess)
            retryReq.end()
            return
          } catch (retryErr) {
            log.error('upgradeHandler retry failed:', retryErr)
          }
        }
        log.error('upgradeHandler error:', e)
        if (!cltSocket.destroyed) {
          cltSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
        }
      })
      attachUpgradeRelay(proxyReq, overwallHook && overwallHook.onSuccess, true)
      proxyReq.end()
    }
    sendWithFallback()
  }
}
