import logger, { setLogger } from "../utils/logger"
import { detectHost } from "../utils/detect-host"
import * as routes from "./routes"
import renderPage from "./pages"
import { init } from "./init"
import { assertConfig } from "./lib/assert"
import { SessionStore } from "./lib/cookie"

import type { NextAuthAction, NextAuthOptions } from "./types"
import type { Cookie } from "./lib/cookie"
import type { ErrorType } from "./pages/error"
import { parse as parseCookie } from "cookie"

export interface RequestInternal {
  /** @default "http://localhost:3000" */
  host?: string
  method?: string
  cookies?: Partial<Record<string, string>>
  headers?: Record<string, any>
  query?: Record<string, any>
  body?: Record<string, any>
  action: NextAuthAction
  providerId?: string
  error?: string
}

export interface NextAuthHeader {
  key: string
  value: string
}

export interface OutgoingResponse<
  Body extends string | Record<string, any> | any[] = any
> {
  status?: number
  headers?: NextAuthHeader[]
  body?: Body
  redirect?: string
  cookies?: Cookie[]
}

export interface NextAuthHandlerParams {
  req: Request | RequestInternal
  options: NextAuthOptions
}

async function getBody(req: Request): Promise<Record<string, any> | undefined> {
  try {
    return await req.json()
  } catch {}
}

// TODO:
async function toInternalRequest(
  req: RequestInternal | Request
): Promise<RequestInternal> {
  if (req instanceof Request) {
    const url = new URL(req.url)
    // TODO: handle custom paths?
    const nextauth = url.pathname.split("/").slice(3)
    const headers = Object.fromEntries(req.headers.entries())
    const query: Record<string, any> = Object.fromEntries(
      url.searchParams.entries()
    )
    query.nextauth = nextauth

    return {
      action: nextauth[0] as NextAuthAction,
      method: req.method,
      headers,
      body: await getBody(req),
      cookies: parseCookie(req.headers.get("cookie") ?? ""),
      providerId: nextauth[1],
      error: url.searchParams.get("error") ?? nextauth[1],
      host: detectHost(headers["x-forwarded-host"] ?? headers.host),
      query,
    }
  }
  return req
}

// 请求的核心处理函数
export async function NextAuthHandler<
  Body extends string | Record<string, any> | any[]
>(params: NextAuthHandlerParams): Promise<OutgoingResponse<Body>> {
  const { options: userOptions, req: incomingRequest } = params

  const req = await toInternalRequest(incomingRequest) // 对请求进行转换

  setLogger(userOptions.logger, userOptions.debug)

  const assertionResult = assertConfig({ options: userOptions, req }) // 断言用户的选项配置

  if (Array.isArray(assertionResult)) {
    assertionResult.forEach(logger.warn)
  } else if (assertionResult instanceof Error) {
    // Bail out early if there's an error in the user config
    logger.error(assertionResult.code, assertionResult)

    const htmlPages = ["signin", "signout", "error", "verify-request"]
    if (!htmlPages.includes(req.action) || req.method !== "GET") {
      const message = `There is a problem with the server configuration. Check the server logs for more information.`
      return {
        status: 500,
        headers: [{ key: "Content-Type", value: "application/json" }],
        body: { message } as any,
      }
    }
    const { pages, theme } = userOptions

    const authOnErrorPage =
      pages?.error && req.query?.callbackUrl?.startsWith(pages.error)

    if (!pages?.error || authOnErrorPage) {
      if (authOnErrorPage) {
        logger.error(
          "AUTH_ON_ERROR_PAGE_ERROR",
          new Error(
            `The error page ${pages?.error} should not require authentication`
          )
        )
      }
      const render = renderPage({ theme })
      return render.error({ error: "configuration" })
    }

    return {
      redirect: `${pages.error}?error=Configuration`,
    }
  }

  const { action, providerId, error, method = "GET" } = req

  // 初始化默认的选项和cookies
  const { options, cookies } = await init({
    userOptions,
    action,
    providerId,
    host: req.host, // 请求的主机 - dev下是http://localhost:3000
    callbackUrl: req.body?.callbackUrl ?? req.query?.callbackUrl,
    csrfToken: req.body?.csrfToken,
    cookies: req.cookies,
    isPost: method === "POST",
  })

  // 创建一个SessionStore实例对象
  const sessionStore = new SessionStore( // 就是缓存req请求中带过来的cookie的
    options.cookies.sessionToken,
    req,
    options.logger
  )

  // 判断请求方法
  if (method === "GET") {
    // 除非用户定义了他们的[自己的页面](https://next-auth.js.org/configuration/pages)
    // 否则这里使用 Preact SSR 渲染一组默认的。
    // signin、signout、verifyRequest、error类型的
    const render = renderPage({ ...options, query: req.query, cookies })
    const { pages } = options // 在init中若用户没有定义pages，那么这个pages为空对象{}
    switch (action) {
      case "providers":
        return (await routes.providers(options.providers)) as any
      case "session": { // 以这个为举例，比如在server端获取session的，那么发送的请求就会走到这里
        // 具体逻辑看routes下的session.ts文件中细节
        const session = await routes.session({ options, sessionStore }) // 返回{body, cookies, headers}
        if (session.cookies) cookies.push(...session.cookies)
        return { ...session, cookies } as any // 返回交给外面去处理
      }
      case "csrf":
        return {
          headers: [{ key: "Content-Type", value: "application/json" }],
          body: { csrfToken: options.csrfToken } as any,
          cookies,
        }
      case "signin":
        if (pages.signIn) {
          let signinUrl = `${pages.signIn}${
            pages.signIn.includes("?") ? "&" : "?"
          }callbackUrl=${encodeURIComponent(options.callbackUrl)}`
          if (error)
            signinUrl = `${signinUrl}&error=${encodeURIComponent(error)}`
          return { redirect: signinUrl, cookies }
        }

        // ******
        return render.signin() // 采用默认的登录页面进行渲染
      case "signout":
        if (pages.signOut) return { redirect: pages.signOut, cookies }

        return render.signout()
      case "callback":
        if (options.provider) {
          const callback = await routes.callback({ // ******第三方登录成功后的回调地址就会请求走到这里
            body: req.body,
            query: req.query,
            headers: req.headers,
            cookies: req.cookies,
            method,
            options,
            sessionStore,
          })
          if (callback.cookies) cookies.push(...callback.cookies)
          return { ...callback, cookies }
        }
        break
      case "verify-request":
        if (pages.verifyRequest) {
          return { redirect: pages.verifyRequest, cookies }
        }
        return render.verifyRequest()
      case "error":
        // These error messages are displayed in line on the sign in page
        if (
          [
            "Signin",
            "OAuthSignin",
            "OAuthCallback",
            "OAuthCreateAccount",
            "EmailCreateAccount",
            "Callback",
            "OAuthAccountNotLinked",
            "EmailSignin",
            "CredentialsSignin",
            "SessionRequired",
          ].includes(error as string)
        ) {
          return { redirect: `${options.url}/signin?error=${error}`, cookies }
        }

        if (pages.error) {
          return {
            redirect: `${pages.error}${
              pages.error.includes("?") ? "&" : "?"
            }error=${error}`,
            cookies,
          }
        }

        return render.error({ error: error as ErrorType })
      default:
    }
  } else if (method === "POST") {
    switch (action) {
      case "signin":
        // Verified CSRF Token required for all sign in routes
        if (options.csrfTokenVerified && options.provider) { // ******https://next-auth-example.vercel.app/例子走的是这个逻辑
          const signin = await routes.signin({ // 会返回一个redirect url，那么之后在next/index.ts中就可以302 location啦 ~
            // ******
            query: req.query,
            body: req.body,
            options,
          })
          if (signin.cookies) cookies.push(...signin.cookies)
          return { ...signin, cookies }
        }

        return { redirect: `${options.url}/signin?csrf=true`, cookies }
      case "signout":
        // Verified CSRF Token required for signout
        if (options.csrfTokenVerified) {
          const signout = await routes.signout({ options, sessionStore })
          if (signout.cookies) cookies.push(...signout.cookies)
          return { ...signout, cookies }
        }
        return { redirect: `${options.url}/signout?csrf=true`, cookies }
      case "callback":
        if (options.provider) {
          // Verified CSRF Token required for credentials providers only
          if (
            options.provider.type === "credentials" &&
            !options.csrfTokenVerified
          ) {
            return { redirect: `${options.url}/signin?csrf=true`, cookies }
          }

          const callback = await routes.callback({
            body: req.body,
            query: req.query,
            headers: req.headers,
            cookies: req.cookies,
            method,
            options,
            sessionStore,
          })
          if (callback.cookies) cookies.push(...callback.cookies)
          return { ...callback, cookies }
        }
        break
      case "_log":
        if (userOptions.logger) {
          try {
            const { code, level, ...metadata } = req.body ?? {}
            logger[level](code, metadata)
          } catch (error) {
            // If logging itself failed...
            logger.error("LOGGER_ERROR", error as Error)
          }
        }
        return {}
      default:
    }
  }

  return {
    status: 400,
    body: `Error: This action with HTTP ${method} is not supported by NextAuth.js` as any,
  }
}
