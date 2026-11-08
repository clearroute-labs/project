import type Privy from '@privy-io/js-sdk-core'

const callbackParameters = ['privy_oauth_code', 'privy_oauth_state', 'privy_oauth_provider'] as const

export function withoutPrivyOAuthCallback(href: string): string {
  const url = new URL(href)
  for (const parameter of callbackParameters) url.searchParams.delete(parameter)
  return url.href
}

export async function completePrivyOAuth(client: Privy, href: string): Promise<void> {
  const url = new URL(href)
  if (!callbackParameters.some((parameter) => url.searchParams.has(parameter))) return
  const [code, state, provider] = callbackParameters.map((parameter) => url.searchParams.get(parameter))
  if (!code || code === 'error' || !state || provider !== 'google') throw new Error('Invalid Google login callback.')

  // The signing window already has an opener. React Auth would forward this
  // redirect to that window as though it had initiated a Privy popup login.
  // Complete it here instead; the SDK validates the saved state and PKCE verifier.
  await client.auth.oauth.loginWithCode(code, state, provider, undefined, 'login-or-sign-up')
  window.history.replaceState(window.history.state, '', withoutPrivyOAuthCallback(href))
}
