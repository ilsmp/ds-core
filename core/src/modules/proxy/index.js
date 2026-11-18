const childProcess = require('node:child_process')

// 系统代理守护：第三方软件（如 FlClash 内核的 VPN 模式客户端）退出时会把
// 系统代理整体关闭，导致 DS 状态显示开启而系统实际已断流。运行期间定期
// 校验系统代理是否仍指向本进程端口，被翻掉就自动恢复（仅 macOS 实现）。
const PROXY_GUARD_INTERVAL_MS = 15000
let proxyGuardTimer = null

function readMacSystemProxyState () {
  return new Promise((resolve) => {
    childProcess.exec('scutil --proxy', { timeout: 5000 }, (err, stdout) => {
      if (err) {
        resolve(null)
        return
      }
      const portMatch = String(stdout || '').match(/HTTPPort\s*:\s*(\d+)/)
      const enabledMatch = String(stdout || '').match(/HTTPEnable\s*:\s*(\d+)/)
      resolve({
        enabled: enabledMatch ? enabledMatch[1] === '1' : null,
        port: portMatch ? Number(portMatch[1]) : null,
      })
    })
  })
}

function startProxyGuard (context, expectedPort) {
  stopProxyGuard()
  proxyGuardTimer = setInterval(async () => {
    try {
      const state = await readMacSystemProxyState()
      if (state == null || state.enabled !== false) {
        return // 读取失败或代理仍开启：不动
      }
      if (state.port != null && state.port !== expectedPort) {
        return // 系统代理指向其他端口（用户切到别的代理软件后关闭），尊重之，不抢
      }
      context.log.warn(`检测到系统代理被第三方软件关闭（期望端口 ${expectedPort}），正在自动恢复...`)
      await context.shell.setSystemProxy({ ip: '127.0.0.1', port: expectedPort, setEnv: false })
      context.log.info('系统代理已自动恢复')
      context.event.fire('status', { key: 'proxy.enabled', value: true })
    } catch (e) {
      context.log.warn('系统代理守护检查失败:', e.message)
    }
  }, PROXY_GUARD_INTERVAL_MS)
  // unref：守护定时器不阻止进程退出
  if (proxyGuardTimer.unref) {
    proxyGuardTimer.unref()
  }
  context.log.info(`系统代理守护已启动（每 ${PROXY_GUARD_INTERVAL_MS / 1000}s 校验一次）`)
}

function stopProxyGuard () {
  if (proxyGuardTimer != null) {
    clearInterval(proxyGuardTimer)
    proxyGuardTimer = null
  }
}

const ProxyPlugin = function (context) {
  const { config, event, shell, log } = context
  const api = {
    async start () {
      const ret = await api.setProxy()
      if (process.platform === 'darwin') {
        startProxyGuard(context, ret.port)
      }
      return ret
    },

    async close () {
      stopProxyGuard()
      return api.unsetProxy()
    },

    async restart () {
      await api.close()
      await api.start()
    },

    async setProxy () {
      const ip = '127.0.0.1'
      const port = config.get().server.port
      const proxyConfig = config.get().proxy || {}
      const setEnv = proxyConfig.setEnv ?? false
      const setCaBundle = proxyConfig.setCaBundle ?? false
      await shell.setSystemProxy({ ip, port, setEnv, setCaBundle })
      log.info(`开启系统代理成功：${ip}:${port}`)
      event.fire('status', { key: 'proxy.enabled', value: true })
      return { ip, port }
    },

    async guardStatus () {
      return {
        running: proxyGuardTimer != null,
        intervalMs: PROXY_GUARD_INTERVAL_MS,
      }
    },

    async unsetProxy (setEnv) {
      if (setEnv == null) {
        const proxyConfig = config.get().proxy || {}
        setEnv = proxyConfig.setEnv ?? false
      }
      try {
        await shell.setSystemProxy({ setEnv })
        event.fire('status', { key: 'proxy.enabled', value: false })
        log.info('关闭系统代理成功')
        return true
      } catch (err) {
        log.error('关闭系统代理失败:', err)
        return false
      }
    },

    async setEnableLoopback () {
      await shell.enableLoopback()
      log.info('打开EnableLoopback成功')
      return true
    },
  }
  return api
}
module.exports = {
  key: 'proxy',
  config: {
    enabled: true,
    name: '系统代理',
    use: 'local',
    other: [],
    proxyHttp: false, // false=只代理HTTPS请求   true=同时代理HTTP和HTTPS请求
    setEnv: false,
    setCaBundle: false,

    // 排除国内域名 所需配置
    excludeDomesticDomainAllowList: true, // 是否排除国内域名，默认：需要排除
    autoUpdateDomesticDomainAllowList: true, // 是否自动更新国内域名
    remoteDomesticDomainAllowListFileUrl: 'https://raw.githubusercontent.com/pluwen/china-domain-allowlist/refs/heads/main/allow-list.sorl',
    domesticDomainAllowListFileAbsolutePath: null, // 自定义 domestic-domain-allowlist.txt 文件位置，可以是本地文件路径
    domesticDomainAllowListFilePath: './extra/proxy/domestic-domain-allowlist.txt', // 内置国内域名文件

    // 自定义系统代理排除列表
    excludeIpList: {
      // region 常用国内可访问域名

      // 中国大陆
      '*.cn': true,
      'cn.*': true,
      '*china*': true,

      // Github加速源：以下加速源代理后反而出现问题，从系统代理中排除掉
      '*.kkgithub.com': true,
      '*.ghproxy.*': true,

      // Github ssh
      'ssh.github.com': true,

      // DeepL
      'www.deepl.com': true,

      // CSDN
      '*.csdn.net': true,

      // 360 so
      '*.so.com': true,

      // 百度
      '*.baidu.com': true,
      '*.baiducontent.com': true,
      '*.bdimg.com': true,
      '*.bdstatic.com': true,
      '*.bdydns.com': true,

      // 腾讯
      '*.tencent.com': true,
      '*.qq.com': true,
      '*.weixin.com': true,
      '*.weixinbridge.com': true,
      '*.wechat.com': true,
      '*.idqqimg.com': true,
      '*.gtimg.com': true,
      '*.qpic.com': true,
      '*.qlogo.com': true,
      '*.myapp.com': true,

      // 阿里
      '*.aliyun.com': true,
      '*.alipay.com': true,
      '*.taobao.com': true,
      '*.tmall.com': true,
      '*.alipayobjects.com': true,
      '*.dingtalk.com': true,
      '*.mmstat.com': true,
      '*.alicdn.com': true,
      '*.hdslb.com': true,

      // Gitee
      'gitee.com': true,
      '*.gitee.com': true,
      '*.gitee.io': true,
      '*.giteeusercontent.com': true,

      // Mozilla Firefox
      '*.mozilla.org': true,
      '*.mozilla.com': true,
      '*.mozilla.net': true,
      '*.firefox.com': true,
      '*.firefox.org': true,
      '*.mozillademos.org': true,
      '*.mozillians.org': true,
      '*.mozillians.net': true,
      '*.mozillians.com': true,

      // OSS
      '*.sonatype.org': true,
      // Maven镜像
      '*.maven.org': true,
      // Maven Repository
      '*.mvnrepository.com': true,

      // 苹果
      '*.apple.com': true,
      '*.icloud.com': true,

      // 微软
      '*.microsoft.com': true,
      '*.windows.com': true,
      '*.office.com': true,
      '*.office.net': true,
      '*.live.com': true,
      '*.msn.com': true,

      // WPS
      '*.wps.com': true,
      '*.wps.net': true,
      '*.ksord.com': true,

      // 奇虎
      '*.qihoo.com': true,
      '*.qihucdn.com': true,
      // 360
      '*.360.com': true,
      '*.360safe.com': true,
      '*.360buyimg.com': true,
      '*.360buy.com': true,

      // 京东
      '*.jd.com': true,
      '*.jcloud.com': true,
      '*.jcloudcs.com': true,
      '*.jcloudcache.com': true,
      '*.jcloudcdn.com': true,
      '*.jcloudlb.com': true,

      // 哔哩哔哩
      '*.bilibili.com': true,
      '*.bilivideo.com': true,
      '*.biliapi.net': true,

      // 移动
      '*.10086.com': true,
      '*.10086cloud.com': true,

      // 移动：139邮箱
      '*.139.com': true,

      // 迅雷
      '*.xunlei.com': true,

      // 网站ICP备案查询
      '*.icpapi.com': true,

      // Navicat
      '*.navicat.com': true,

      // Github文件上传所使用的域名，被DS代理会导致文件上传经常失败，从系统代理中排除掉
      'objects-origin.githubusercontent.com': true,

      // cloudflare：排除以下域名，cloudflare的人机校验会更快，成功率更高。
      'challenges.cloudflare.com': true,

      // endregion

      // 本地地址，无需代理
      'localhost': true,
      'localhost.*': true, // 部分VPN会在host中添加这种格式的域名指向127.0.0.1，所以也排除掉
      '127.*.*.*': true,
      'test.*': true, // 本地开发时，测试用的虚拟域名格式，无需代理

      // 服务器端常用地址，无需代理
      '10.*.*.*': true,
      '172.16.*.*': true,
      '172.17.*.*': true,
      '172.18.*.*': true,
      '172.19.*.*': true,
      '172.20.*.*': true,
      '172.21.*.*': true,
      '172.22.*.*': true,
      '172.23.*.*': true,
      '172.24.*.*': true,
      '172.25.*.*': true,
      '172.26.*.*': true,
      '172.27.*.*': true,
      '172.28.*.*': true,
      '172.29.*.*': true,
      '172.30.*.*': true,
      '172.31.*.*': true,

      // 局域网地址，无需代理
      '192.168.*.*': true,
    },
  },
  status: {
    enabled: false,
    proxyTarget: '',
  },
  plugin: ProxyPlugin,
}
