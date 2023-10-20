
declare module '@neumatter/uri'

export interface URIOptions {
  reference?: string
  scheme?: string
  unicodeSupport?: boolean
  domainHost?: boolean
  skipEscape?: boolean
}

export default class URI {
  constructor (uri: string | URI | URL, opts?: URIOptions)
  get scheme (): string
  get userinfo (): string
  get host (): string
  get port (): string
  get path (): string
  get query (): string
  get fragment (): string
  get reference (): 'relative' | 'absolute'
  toString (): string
}
