import { fromDate } from "../lib/utils"

import type { Adapter } from "../../adapters"
import type { InternalOptions } from "../types"
import type { OutgoingResponse } from ".."
import type { Session } from "../.."
import type { SessionStore } from "../lib/cookie"

interface SessionParams {
  options: InternalOptions
  sessionStore: SessionStore
}

/**
 * Return a session object (without any private fields)
 * for Single Page App clients
 */

export default async function session(
  params: SessionParams
): Promise<OutgoingResponse<Session | {}>> {
  const { options, sessionStore } = params
  const {
    adapter,
    jwt,
    events,
    callbacks,
    logger,
    session: { strategy: sessionStrategy, maxAge: sessionMaxAge },
  } = options

  // 详细请看init.ts中的具体逻辑
  // session策略 - sessionStrategy
  // 如果未指定适配器，则强制使用jwt（无状态）
  // 有适配器的话那么就使用database - 数据库

  const response: OutgoingResponse<Session | {}> = {
    body: {},
    headers: [{ key: "Content-Type", value: "application/json" }],
    cookies: [],
  }

  const sessionToken = sessionStore.value // 就是req带过来的cookie值字符串

  if (!sessionToken) return response // 没有直接返回response就可啦

  // 未指定adapt的话默认的session的策略是jwt的方式
  if (sessionStrategy === "jwt") {
    try {
      const decodedToken = await jwt.decode({ // init.ts中使用的decode方法 - 解码
        ...jwt,
        token: sessionToken,
      })

      const newExpires = fromDate(sessionMaxAge)

      // By default, only exposes a limited subset of information to the client
      // as needed for presentation purposes (e.g. "you are logged in as...").
      const session = {
        user: {
          name: decodedToken?.name,
          email: decodedToken?.email,
          image: decodedToken?.picture,
        },
        expires: newExpires.toISOString(),
      }

      // @ts-expect-error
      const token = await callbacks.jwt({ token: decodedToken }) /// 执行用户选项中的callbacks对象中的jwt方法
      // @ts-expect-error
      const newSession = await callbacks.session({ session, token }) // 执行用户选项中的callbacks对象中的session方法

      // Return session payload as response
      response.body = newSession // 直接作为body响应回去

      // Refresh JWT expiry by re-signing it, with an updated expiry date
      const newToken = await jwt.encode({ // jwt编码
        ...jwt,
        token,
        maxAge: options.session.maxAge,
      })

      // Set cookie, to also update expiry date on cookie
      const sessionCookies = sessionStore.chunk(newToken, {
        expires: newExpires,
      }) // 转为cookie

      // 把cookie存放如响应的cookies中
      response.cookies?.push(...sessionCookies) // 这样在响应中携带cookie，那么浏览器就能够存入cookie啦

      await events.session?.({ session: newSession, token })
    } catch (error) {
      // If JWT not verifiable, make sure the cookie for it is removed and return empty object
      logger.error("JWT_SESSION_ERROR", error as Error)

      response.cookies?.push(...sessionStore.clean())
    }
  } else {
    // 有适配器 - 在next-auth仓库下与next-auth同发行的依赖包中还有大量的类似于adapter-mongodb、adapter-sequelize等依赖包
    // 那么这个便可以在用户选项中指定adapter了，肯定是引入相应的适配器，这些适配器其实就是数据库
    // session策略为database - 数据库的方式
    try {
      const { getSessionAndUser, deleteSession, updateSession } =
        adapter as Adapter // 从适配器中获取对session操作的一系列的方法函数
      // 其实说白了就是拿到对数据库的获取、删除、更新操作的一系列方法
      
      // 从数据库中依据req携带来的cookie获取session
      let userAndSession = await getSessionAndUser(sessionToken) // 根据cookie字符串获取session

      // 判断数据库中的session值是否过期
      // If session has expired, clean up the database
      if (
        userAndSession &&
        userAndSession.session.expires.valueOf() < Date.now()
      ) {
        await deleteSession(sessionToken)
        userAndSession = null
      }

      // session值没有过期且有session
      if (userAndSession) {
        const { user, session } = userAndSession

        const sessionUpdateAge = options.session.updateAge
        // Calculate last updated date to throttle write updates to database
        // Formula: ({expiry date} - sessionMaxAge) + sessionUpdateAge
        //     e.g. ({expiry date} - 30 days) + 1 hour
        const sessionIsDueToBeUpdatedDate =
          session.expires.valueOf() -
          sessionMaxAge * 1000 +
          sessionUpdateAge * 1000

        const newExpires = fromDate(sessionMaxAge)
        // Trigger update of session expiry date and write to database, only
        // if the session was last updated more than {sessionUpdateAge} ago
        if (sessionIsDueToBeUpdatedDate <= Date.now()) {
          await updateSession({ sessionToken, expires: newExpires }) // 更新session的过期时间
        }

        // Pass Session through to the session callback
        // @ts-expect-error
        const sessionPayload = await callbacks.session({
          // By default, only exposes a limited subset of information to the client
          // as needed for presentation purposes (e.g. "you are logged in as...").
          session: {
            user: {
              name: user.name,
              email: user.email,
              image: user.image,
            },
            expires: session.expires.toISOString(),
          },
          user,
        })

        // Return session payload as response
        response.body = sessionPayload

        // Set cookie again to update expiry
        response.cookies?.push({
          name: options.cookies.sessionToken.name,
          value: sessionToken,
          options: {
            ...options.cookies.sessionToken.options,
            expires: newExpires,
          },
        })

        // @ts-expect-error
        await events.session?.({ session: sessionPayload })
      } else if (sessionToken) { // 没有session啦，但是有客户端带过来的cookie值
        // If `sessionToken` was found set but it's not valid for a session then
        // remove the sessionToken cookie from browser.
        response.cookies?.push(...sessionStore.clean()) // 让客户端把cookie删除掉，因为这是一个无效的，在数据库中查不到，所以让客户端进行删除
      }
    } catch (error) {
      logger.error("SESSION_ERROR", error as Error)
    }
  }

  // 返回响应对象
  return response
}
