import type { InternalProvider, Theme } from "../types"

/**
 * The following errors are passed as error query parameters to the default or overridden sign-in page.
 *
 * [Documentation](https://next-auth.js.org/configuration/pages#sign-in-page) */
export type SignInErrorTypes =
  | "Signin"
  | "OAuthSignin"
  | "OAuthCallback"
  | "OAuthCreateAccount"
  | "EmailCreateAccount"
  | "Callback"
  | "OAuthAccountNotLinked"
  | "EmailSignin"
  | "CredentialsSignin"
  | "SessionRequired"
  | "default"

export interface SignInServerPageParams {
  csrfToken: string
  providers: InternalProvider[]
  callbackUrl: string
  email: string
  error: SignInErrorTypes
  theme: Theme
}

export default function SigninPage(props: SignInServerPageParams) {
  const {
    csrfToken,
    providers,
    callbackUrl,
    theme,
    email,
    error: errorType,
  } = props
  // ***
  // 根据用户配置的providers来去决定最终渲染的页面
  // ***
  // We only want to render providers
  const providersToRender = providers.filter((provider) => {
    if (provider.type === "oauth" || provider.type === "email") {
      // Always render oauth and email type providers
      return true
    } else if (provider.type === "credentials" && provider.credentials) {
      // Only render credentials type provider if credentials are defined
      return true
    }
    // Don't render other provider types
    return false
  })

  if (typeof document !== "undefined" && theme.brandColor) {
    document.documentElement.style.setProperty(
      "--brand-color",
      theme.brandColor
    )
  }

  const errors: Record<SignInErrorTypes, string> = {
    Signin: "Try signing in with a different account.",
    OAuthSignin: "Try signing in with a different account.",
    OAuthCallback: "Try signing in with a different account.",
    OAuthCreateAccount: "Try signing in with a different account.",
    EmailCreateAccount: "Try signing in with a different account.",
    Callback: "Try signing in with a different account.",
    OAuthAccountNotLinked:
      "To confirm your identity, sign in with the same account you used originally.",
    EmailSignin: "The e-mail could not be sent.",
    CredentialsSignin:
      "Sign in failed. Check the details you provided are correct.",
    SessionRequired: "Please sign in to access this page.",
    default: "Unable to sign in.",
  }

  const error = errorType && (errors[errorType] ?? errors.default)

  return (
    <div className="signin">
      {theme.brandColor && (
        <style
          dangerouslySetInnerHTML={{
            __html: `
        :root {
          --brand-color: ${theme.brandColor}
        }
      `,
          }}
        />
      )}
      {theme.logo && <img src={theme.logo} alt="Logo" className="logo" />}
      <div className="card">
        {error && (
          <div className="error">
            <p>{error}</p>
          </div>
        )}
        {providersToRender.map((provider, i: number) => (
          <div key={provider.id} className="provider">
            {provider.type === "oauth" && ( // github provider的signinUrl是https://next-auth-example.vercel.app/api/auth/signin/github post请求
              <form action={provider.signinUrl} method="POST">
                <input type="hidden" name="csrfToken" value={csrfToken} />
                {/** ****** */}
                {/** callbackUrl在dev下是http://localhost:3000，生产下是https://next-auth-example.vercel.app/为例子
                 * 
                 * 点击github登录就会发送https://next-auth-example.vercel.app/api/auth/signin/github post请求
                 * 
                 * 之后该请求响应为302 响应头中附带location头地址为
                 * https://github.com/login/oauth/authorize?client_id=bce1a4f72ad55855cb9a&scope=read:user user:email&response_type=code&redirect_uri=https://next-auth-example.vercel.app/api/auth/callback/github&state=UJYCJQlAo1vdYPQJURxWO2TB16UcLB3hmmDWUmV5n80
                 * 从url分析得知登录成功后重定向的url是https://next-auth-example.vercel.app/api/auth/callback/github
                 * 
                 * 之后浏览器就跳转到这个地址 - 让用户同意授权
                 * 
                 * 授权之后跳转到https://next-auth-example.vercel.app/api/auth/callback/github
                 * 
                 * 此时便来到了core/routes/callback.ts中来 - 经过一系列的处理 - jwt encode - 转为cookie形式 - redirect为callbackUrl
                 * 数据库策略的话主要逻辑在core/lib/callback-handler.ts中进行向数据库中创建用户以及像数据库中创建session等操作
                 * 
                 * 在next/index.ts中响应302 location为callbackUrl 附带cookie
                 * 
                 * 浏览器再做跳转到到callbackUrl
                 * 
                 * 如果是客户端做session的逻辑
                 * 那么客户端会发出/api/auth/session的请求 - 注意：会附带带有jwt的cookie -> 来到routes/session.ts中
                 * 默认是jwt策略，之后就会对jwt进行decode等一些列的操作
                 * 数据库策略的话就会通过cookie向数据库中查询等操作
                 * 
                 * 具体例子可参考https://github.com/benxiaohaiw/next-auth-example
                 * https://next-auth-example.vercel.app/
                 * 
                 */}
                {callbackUrl && (
                  <input type="hidden" name="callbackUrl" value={callbackUrl} />
                )}
                <button type="submit" className="button">
                  Sign in with {provider.name}
                </button>
              </form>
            )}
            {(provider.type === "email" || provider.type === "credentials") &&
              i > 0 &&
              providersToRender[i - 1].type !== "email" &&
              providersToRender[i - 1].type !== "credentials" && <hr />}
            {provider.type === "email" && (
              <form action={provider.signinUrl} method="POST">
                <input type="hidden" name="csrfToken" value={csrfToken} />
                <label
                  className="section-header"
                  htmlFor={`input-email-for-${provider.id}-provider`}
                >
                  Email
                </label>
                <input
                  id={`input-email-for-${provider.id}-provider`}
                  autoFocus
                  type="email"
                  name="email"
                  value={email}
                  placeholder="email@example.com"
                  required
                />
                <button type="submit">Sign in with {provider.name}</button>
              </form>
            )}
            {provider.type === "credentials" && (
              <form action={provider.callbackUrl} method="POST">
                <input type="hidden" name="csrfToken" value={csrfToken} />
                {Object.keys(provider.credentials).map((credential) => {
                  return (
                    <div key={`input-group-${provider.id}`}>
                      <label
                        className="section-header"
                        htmlFor={`input-${credential}-for-${provider.id}-provider`}
                      >
                        {provider.credentials[credential].label ?? credential}
                      </label>
                      <input
                        name={credential}
                        id={`input-${credential}-for-${provider.id}-provider`}
                        type={provider.credentials[credential].type ?? "text"}
                        placeholder={
                          provider.credentials[credential].placeholder ?? ""
                        }
                        {...provider.credentials[credential]}
                      />
                    </div>
                  )
                })}
                <button type="submit">Sign in with {provider.name}</button>
              </form>
            )}
            {(provider.type === "email" || provider.type === "credentials") &&
              i + 1 < providersToRender.length && <hr />}
          </div>
        ))}
      </div>
    </div>
  )
}
