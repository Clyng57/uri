'use strict'

import Url from 'url'
import { normalizeIPv6, normalizeIPv4, removeDotSegments, recomposeAuthority, normalizeComponentEncoding } from './lib/utils.js'
import SCHEMES from './lib/schemes.js'

function normalize (uri, options) {
  if (typeof uri === 'string') {
    uri = serialize(parse(uri, options), options)
  } else if (typeof uri === 'object') {
    uri = parse(serialize(uri, options), options)
  }
  return uri
}

function resolve (baseURI, relativeURI, options) {
  const schemelessOptions = Object.assign({ scheme: 'null' }, options)
  const resolved = resolveComponents(parse(baseURI, schemelessOptions), parse(relativeURI, schemelessOptions), schemelessOptions, true)
  return serialize(resolved, { ...schemelessOptions, skipEscape: true })
}

function resolveComponents (base, relative, options, skipNormalization) {
  const target = {}
  if (!skipNormalization) {
    base = parse(serialize(base, options), options) // normalize base components
    relative = parse(serialize(relative, options), options) // normalize relative components
  }
  options = options || {}

  if (!options.tolerant && relative.scheme) {
    target.scheme = relative.scheme
    // target.authority = relative.authority;
    target.userinfo = relative.userinfo
    target.host = relative.host
    target.port = relative.port
    target.path = removeDotSegments(relative.path || '')
    target.query = relative.query
  } else {
    if (relative.userinfo !== undefined || relative.host !== undefined || relative.port !== undefined) {
      // target.authority = relative.authority;
      target.userinfo = relative.userinfo
      target.host = relative.host
      target.port = relative.port
      target.path = removeDotSegments(relative.path || '')
      target.query = relative.query
    } else {
      if (!relative.path) {
        target.path = base.path
        if (relative.query !== undefined) {
          target.query = relative.query
        } else {
          target.query = base.query
        }
      } else {
        if (relative.path.charAt(0) === '/') {
          target.path = removeDotSegments(relative.path)
        } else {
          if ((base.userinfo !== undefined || base.host !== undefined || base.port !== undefined) && !base.path) {
            target.path = '/' + relative.path
          } else if (!base.path) {
            target.path = relative.path
          } else {
            target.path = base.path.slice(0, base.path.lastIndexOf('/') + 1) + relative.path
          }
          target.path = removeDotSegments(target.path)
        }
        target.query = relative.query
      }
      // target.authority = base.authority;
      target.userinfo = base.userinfo
      target.host = base.host
      target.port = base.port
    }
    target.scheme = base.scheme
  }

  target.fragment = relative.fragment

  return target
}

function equal (uriA, uriB, options) {
  if (typeof uriA === 'string') {
    uriA = safeDecodeURI(uriA)
    uriA = serialize(normalizeComponentEncoding(parse(uriA, options), true), { ...options, skipEscape: true })
  } else if (typeof uriA === 'object') {
    uriA = serialize(normalizeComponentEncoding(uriA, true), { ...options, skipEscape: true })
  }

  if (typeof uriB === 'string') {
    uriB = safeDecodeURI(uriB)
    uriB = serialize(normalizeComponentEncoding(parse(uriB, options), true), { ...options, skipEscape: true })
  } else if (typeof uriB === 'object') {
    uriB = serialize(normalizeComponentEncoding(uriB, true), { ...options, skipEscape: true })
  }

  return uriA.toLowerCase() === uriB.toLowerCase()
}

// Escaped characters. Use empty strings to fill up unused entries.
// Using Array is faster than Object/Map
const escapedCodes = [
  /* 0 - 9 */ '', '', '', '', '', '', '', '', '', '%09',
  /* 10 - 19 */ '%0A', '', '', '%0D', '', '', '', '', '', '',
  /* 20 - 29 */ '', '', '', '', '', '', '', '', '', '',
  /* 30 - 39 */ '', '', '%20', '', '%22', '', '', '', '', '%27',
  /* 40 - 49 */ '', '', '', '', '', '', '', '', '', '',
  /* 50 - 59 */ '', '', '', '', '', '', '', '', '', '',
  /* 60 - 69 */ '%3C', '', '%3E', '', '', '', '', '', '', '',
  /* 70 - 79 */ '', '', '', '', '', '', '', '', '', '',
  /* 80 - 89 */ '', '', '', '', '', '', '', '', '', '',
  /* 90 - 99 */ '', '', '%5C', '', '%5E', '', '%60', '', '', '',
  /* 100 - 109 */ '', '', '', '', '', '', '', '', '', '',
  /* 110 - 119 */ '', '', '', '', '', '', '', '', '', '',
  /* 120 - 125 */ '', '', '', '%7B', '%7C', '%7D',
]

// Automatically escape all delimiters and unwise characters from RFC 2396.
// Also escape single quotes in case of an XSS attack.
// Return the escaped string.
export function escapeString (rest) {
  let escaped = ''
  let lastEscapedPos = 0
  for (let i = 0; i < rest.length; ++i) {
    // `escaped` contains substring up to the last escaped character.
    const escapedChar = escapedCodes[rest.charCodeAt(i)]
    if (escapedChar) {
      // Concat if there are ordinary characters in the middle.
      if (i > lastEscapedPos) escaped += rest.slice(lastEscapedPos, i)
      escaped += escapedChar
      lastEscapedPos = i + 1
    }
  }
  if (lastEscapedPos === 0) { // Nothing has been escaped.
    return rest
  }
  // There are ordinary characters at the end.
  if (lastEscapedPos < rest.length) {
    escaped += rest.slice(lastEscapedPos)
  }

  return escaped
}

function serialize (cmpts, opts) {
  const components = {
    host: cmpts.host,
    scheme: cmpts.scheme,
    userinfo: cmpts.userinfo,
    port: cmpts.port,
    path: cmpts.path,
    query: cmpts.query,
    nid: cmpts.nid,
    nss: cmpts.nss,
    uuid: cmpts.uuid,
    fragment: cmpts.fragment,
    reference: cmpts.reference,
    resourceName: cmpts.resourceName,
    secure: cmpts.secure,
    error: ''
  }
  const options = Object.assign({}, opts)
  const uriTokens = []

  // find scheme handler
  const schemeHandler = SCHEMES[(options.scheme || components.scheme || '').toLowerCase()]

  // perform scheme specific serialization
  if (schemeHandler && schemeHandler.serialize) schemeHandler.serialize(components, options)

  if (components.path !== undefined) {
    if (!options.skipEscape) {
      components.path = escapeString(components.path)

      if (components.scheme !== undefined) {
        components.path = components.path.split('%3A').join(':')
      }
    } else {
      components.path = safeDecodeURI(components.path)
    }
  }

  if (options.reference !== 'suffix' && components.scheme) {
    uriTokens.push(components.scheme)
    uriTokens.push(':')
  }

  const authority = recomposeAuthority(components, options)
  if (authority !== undefined) {
    if (options.reference !== 'suffix') {
      uriTokens.push('//')
    }

    uriTokens.push(authority)

    if (components.path && components.path.charAt(0) !== '/') {
      uriTokens.push('/')
    }
  }
  if (components.path !== undefined) {
    let s = components.path

    if (!options.absolutePath && (!schemeHandler || !schemeHandler.absolutePath)) {
      s = removeDotSegments(s)
    }

    if (authority === undefined) {
      s = s.replace(/^\/\//, '/%2F') // don't allow the path to start with "//"
    }

    uriTokens.push(s)
  }

  if (components.query !== undefined) {
    uriTokens.push('?')
    uriTokens.push(components.query)
  }

  if (components.fragment !== undefined) {
    uriTokens.push('#')
    uriTokens.push(components.fragment)
  }
  return uriTokens.join('')
}

const hexLookUp = Array.from({ length: 127 }, (v, k) => /[^!"$&'()*+,.;=_`a-z{}~-]/.test(String.fromCharCode(k)))

function nonSimpleDomain (value) {
  let code = 0
  for (let i = 0, len = value.length; i < len; ++i) {
    code = value.charCodeAt(i)
    if (code > 126 || hexLookUp[code]) {
      return true
    }
  }
  return false
}

const URI_PARSE = /^(?:([^:/?#]+):)?(?:\/\/((?:([^/?#@]*)@)?(\[[^/?#\]]+\]|[^/?#:]*)(?::(\d*))?))?([^?#]*)(?:\?([^#]*))?(?:#((?:.|\n|\r)*))?/i

function parse (uri, opts) {
  const options = Object.assign({}, opts)
  const parsed = {
    scheme: undefined,
    userinfo: undefined,
    host: '',
    port: undefined,
    path: '',
    query: undefined,
    fragment: undefined
  }
  const gotEncoding = uri.indexOf('%') !== -1
  if (options.reference === 'suffix') uri = (options.scheme ? options.scheme + ':' : '') + '//' + uri

  const matches = uri.match(URI_PARSE)

  if (matches) {
    // store each component
    parsed.scheme = matches[1]
    parsed.userinfo = matches[3]
    parsed.host = matches[4]
    parsed.port = parseInt(matches[5], 10)
    parsed.path = matches[6] || ''
    parsed.query = matches[7]
    parsed.fragment = matches[8]

    // fix port number
    if (isNaN(parsed.port)) {
      parsed.port = matches[5]
    }
    if (parsed.host) {
      const ipv4result = normalizeIPv4(parsed.host)
      if (ipv4result.isIPV4 === false) {
        parsed.host = normalizeIPv6(ipv4result.host, { isIPV4: false }).host.toLowerCase()
      } else {
        parsed.host = ipv4result.host
      }
    }
    if (parsed.scheme === undefined && parsed.userinfo === undefined && parsed.host === undefined && parsed.port === undefined && !parsed.path && parsed.query === undefined) {
      parsed.reference = 'same-document'
    } else if (parsed.scheme === undefined) {
      parsed.reference = 'relative'
    } else if (parsed.fragment === undefined) {
      parsed.reference = 'absolute'
    } else {
      parsed.reference = 'uri'
    }

    // check for reference errors
    if (options.reference && options.reference !== 'suffix' && options.reference !== parsed.reference) {
      parsed.error = parsed.error || 'URI is not a ' + options.reference + ' reference.'
    }

    // find scheme handler
    const schemeHandler = SCHEMES[(options.scheme || parsed.scheme || '').toLowerCase()]

    // check if scheme can't handle IRIs
    if (!options.unicodeSupport && (!schemeHandler || !schemeHandler.unicodeSupport)) {
      // if host component is a domain name
      if (parsed.host && (options.domainHost || (schemeHandler && schemeHandler.domainHost)) && nonSimpleDomain(parsed.host)) {
        // convert Unicode IDN -> ASCII IDN
        try {
          parsed.host = Url.domainToASCII(parsed.host.toLowerCase())
        } catch (e) {
          parsed.error = parsed.error || "Host's domain name can not be converted to ASCII: " + e
        }
      }
      // convert IRI -> URI
    }

    if (!schemeHandler || (schemeHandler && !schemeHandler.skipNormalize)) {
      if (gotEncoding && parsed.scheme !== undefined) {
        parsed.scheme = safeDecodeURI(parsed.scheme)
      }
      if (gotEncoding && parsed.userinfo !== undefined) {
        parsed.userinfo = safeDecodeURI(parsed.userinfo)
      }
      if (gotEncoding && parsed.host !== undefined) {
        parsed.host = safeDecodeURI(parsed.host)
      }
      if (parsed.path !== undefined && parsed.path.length) {
        parsed.path = escapeString(parsed.path)
      }
      if (parsed.fragment !== undefined && parsed.fragment.length) {
        parsed.fragment = escapeString(decodeURI(parsed.fragment))
      }
    }

    // perform scheme specific parsing
    if (schemeHandler && schemeHandler.parse) {
      schemeHandler.parse(parsed, options)
    }
  } else {
    parsed.error = parsed.error || 'URI can not be parsed.'
  }
  return parsed
}

// The chars are: # $ & + , / : ; = ? @
function decodeComponentChar (highCharCode, lowCharCode) {
  if (highCharCode === 50) {
    if (lowCharCode === 53) return '%'

    if (lowCharCode === 51) return '#'
    if (lowCharCode === 52) return '$'
    if (lowCharCode === 54) return '&'
    if (lowCharCode === 66) return '+'
    if (lowCharCode === 98) return '+'
    if (lowCharCode === 67) return ','
    if (lowCharCode === 99) return ','
    if (lowCharCode === 70) return '/'
    if (lowCharCode === 102) return '/'
    return null
  }
  if (highCharCode === 51) {
    if (lowCharCode === 65) return ':'
    if (lowCharCode === 97) return ':'
    if (lowCharCode === 66) return ';'
    if (lowCharCode === 98) return ';'
    if (lowCharCode === 68) return '='
    if (lowCharCode === 100) return '='
    if (lowCharCode === 70) return '?'
    if (lowCharCode === 102) return '?'
    return null
  }
  if (highCharCode === 52 && lowCharCode === 48) {
    return '@'
  }
  return null
}

export function safeDecodeURI (path) {
  let shouldDecode = false

  for (let i = 1; i < path.length; i++) {
    const charCode = path.charCodeAt(i)

    if (charCode === 37) {
      const highCharCode = path.charCodeAt(i + 1)
      const lowCharCode = path.charCodeAt(i + 2)

      if (decodeComponentChar(highCharCode, lowCharCode) === null) {
        shouldDecode = true
      } else {
        // %25 - encoded % char. We need to encode one more time to prevent double decoding
        if (highCharCode === 50 && lowCharCode === 53) {
          shouldDecode = true
          path = path.slice(0, i + 1) + '25' + path.slice(i + 1)
          i += 2
        }
        i += 2
      }
    // Some systems do not follow RFC and separate the path and query
    // string with a `;` character (code 59), e.g. `/foo;jsessionid=123456`.
    // Thus, we need to split on `;` as well as `?` and `#`.
    } else if (charCode === 63 || charCode === 59 || charCode === 35) {
      break
    }
  }
  const decodedPath = shouldDecode ? decodeURI(path) : path
  return decodedPath
}

// This class provides the internal state of a Url object. An instance of this
// class is stored in every Url object and is accessed internally by setters
// and getters. It roughly corresponds to the concept of a Url record in the
// Url Standard, with a few differences. It is also the object transported to
// the C++ binding.
// Refs: https://url.spec.whatwg.org/#concept-url
class URIContext {
  // This is the maximum value uint32_t can get.
  // Ada uses uint32_t(-1) for declaring omitted values.
  static #omitted = 4294967295

  href = ''
  schemeEnd = URIContext.#omitted
  userinfoEnd = URIContext.#omitted
  hostStart = URIContext.#omitted
  hostEnd = URIContext.#omitted
  pathStart = URIContext.#omitted
  queryStart = URIContext.#omitted
  fragmentStart = URIContext.#omitted
  port = URIContext.#omitted
  isIPV4 = 0
  isIPV6 = 0

  get hasUserinfo () {
    return this.userinfoEnd !== URIContext.#omitted
  }

  get hasHost () {
    return this.hostStart !== URIContext.#omitted
  }

  get hasPort () {
    return this.port !== URIContext.#omitted
  }

  get hasQuery () {
    return this.queryStart !== URIContext.#omitted
  }

  get hasFragment () {
    return this.fragmentStart !== URIContext.#omitted
  }

  get hasScheme () {
    return this.schemeEnd !== URIContext.#omitted
  }

  get hasPath () {
    return this.pathStart !== URIContext.#omitted
  }
}

export default class URI {
  #context = new URIContext()
  #reference

  constructor (uri, opts) {
    if (uri instanceof URI || uri instanceof URL) {
      uri = uri.toString()
    }

    const options = Object.assign({}, opts)
    const parsed = {
      scheme: undefined,
      userinfo: undefined,
      host: '',
      port: undefined,
      path: '',
      query: undefined,
      fragment: undefined
    }

    const gotEncoding = uri.indexOf('%') !== -1
    if (options.reference === 'suffix') uri = (options.scheme ? options.scheme + ':' : '') + '//' + uri

    const matches = uri.match(URI_PARSE)

    if (matches) {
      // store each component
      parsed.scheme = matches[1]
      parsed.userinfo = matches[3]
      parsed.host = matches[4]
      parsed.port = matches[5]
      parsed.path = matches[6] || ''
      parsed.query = matches[7]
      parsed.fragment = matches[8]

      if (parsed.host) {
        const ipv4result = normalizeIPv4(parsed.host)
        if (ipv4result.isIPV4 === false) {
          parsed.host = normalizeIPv6(ipv4result.host, { isIPV4: false }).host.toLowerCase()
        } else {
          parsed.host = ipv4result.host
        }
      }

      if (parsed.scheme === undefined && parsed.userinfo === undefined && parsed.host === undefined && parsed.port === undefined && !parsed.path && parsed.query === undefined) {
        parsed.reference = 'same-document'
      } else if (parsed.scheme === undefined) {
        parsed.reference = 'relative'
      } else if (parsed.fragment === undefined) {
        parsed.reference = 'absolute'
      } else {
        parsed.reference = 'uri'
      }

      // check for reference errors
      if (options.reference && options.reference !== 'suffix' && options.reference !== parsed.reference) {
        parsed.error = parsed.error || 'URI is not a ' + options.reference + ' reference.'
      }

      // find scheme handler
      const schemeHandler = SCHEMES[(options.scheme || parsed.scheme || '').toLowerCase()]

      // check if scheme can't handle IRIs
      if (!options.unicodeSupport) {
        // if host component is a domain name
        if (parsed.host && (options.domainHost || (schemeHandler && schemeHandler.domainHost)) && nonSimpleDomain(parsed.host)) {
          // convert Unicode IDN -> ASCII IDN
          try {
            parsed.host = Url.domainToASCII(parsed.host.toLowerCase())
          } catch (e) {
            parsed.error = parsed.error || "Host's domain name can not be converted to ASCII: " + e
          }
        }
        // convert IRI -> URI
      }

      if (!schemeHandler || (schemeHandler && !schemeHandler.skipNormalize)) {
        if (gotEncoding && parsed.scheme !== undefined) {
          parsed.scheme = safeDecodeURI(parsed.scheme)
        }
        if (gotEncoding && parsed.userinfo !== undefined) {
          parsed.userinfo = safeDecodeURI(parsed.userinfo)
        }
        if (gotEncoding && parsed.host !== undefined) {
          parsed.host = safeDecodeURI(parsed.host)
        }
        if (parsed.path !== undefined && parsed.path.length) {
          parsed.path = encodeURI(parsed.path)
        }
        if (parsed.query !== undefined && parsed.query.length) {
          parsed.query = encodeURI(safeDecodeURI(parsed.query))
        }
        if (parsed.fragment !== undefined && parsed.fragment.length) {
          parsed.fragment = encodeURI(safeDecodeURI(parsed.fragment))
        }
      }

      if (parsed.path !== undefined && !options.skipEscape) {
        parsed.path = encodeURI(parsed.path)

        if (parsed.scheme !== undefined) {
          parsed.path = parsed.path.split('%3A').join(':')
        }
      } else {
        parsed.path = safeDecodeURI(parsed.path)
      }

      if (options.reference !== 'suffix' && parsed.scheme) {
        this.#context.href += parsed.scheme
        this.#context.schemeEnd = this.#context.href.length
        this.#context.href += ':'
      }

      if (options.reference !== 'suffix' && (parsed.userinfo !== undefined || parsed.host !== undefined)) {
        this.#context.href += '//'
      }

      if (parsed.userinfo !== undefined) {
        this.#context.href += parsed.userinfo
        this.#context.userinfoEnd = this.#context.href.length
        this.#context.href += '@'
      }

      if (parsed.host !== undefined) {
        this.#context.hostStart = this.#context.href.length
        let host = safeDecodeURI(parsed.host)
        const ipV4res = normalizeIPv4(host)

        if (ipV4res.isIPV4) {
          this.#context.isIPV4 = 1
          host = ipV4res.host
        } else {
          const ipV6res = normalizeIPv6(ipV4res.host, { isIPV4: false })
          if (ipV6res.isIPV6 === true) {
            this.#context.isIPV6 = 1
            host = `[${ipV6res.escapedHost}]`
          } else {
            host = parsed.host
          }
        }

        this.#context.href += host
        this.#context.hostEnd = this.#context.href.length
      }

      if (
        typeof parsed.port === 'number' ||
        typeof parsed.port === 'string'
      ) {
        this.#context.href += ':' + String(parsed.port)
        this.#context.port = Number(parsed.port)
      }

      if (parsed.path) {
        this.#context.pathStart = this.#context.href.length
      }

      const hasHost = this.#context.hasHost || this.#context.hasUserinfo

      if (hasHost) {
        if (parsed.path && parsed.path.charAt(0) !== '/') {
          this.#context.href += '/'
        }
      }

      if (parsed.path !== undefined) {
        let s = parsed.path

        if (!options.absolutePath && (!schemeHandler || !schemeHandler.absolutePath)) {
          s = removeDotSegments(s)
        }

        if (hasHost === undefined) {
          s = s.replace(/^\/\//, '/%2F') // don't allow the path to start with "//"
        }

        this.#context.href += s
      }

      if (parsed.query !== undefined) {
        this.#context.queryStart = this.#context.href.length
        this.#context.href += '?' + parsed.query
      }

      if (parsed.fragment !== undefined) {
        this.#context.fragmentStart = this.#context.href.length
        this.#context.href += '#' + parsed.fragment
      }

      this.#reference = parsed.reference
      // perform scheme specific parsing
      // if (schemeHandler && schemeHandler.parse) {
      //  schemeHandler.parse(parsed, options)
      // }
    } else {
      parsed.error = parsed.error || 'URI can not be parsed.'
    }
  }

  get scheme () {
    if (!this.#context.hasScheme) {
      return ''
    }

    return this.#context.href.slice(0, this.#context.schemeEnd)
  }

  get userinfo () {
    if (!this.#context.hasUserinfo) {
      return ''
    }

    return this.#context.href.slice(this.#context.schemeEnd + 3, this.#context.userinfoEnd)
  }

  get host () {
    if (!this.#context.hasHost) {
      return ''
    }

    return this.#context.href.slice(this.#context.hostStart, this.#context.hostEnd)
  }

  get port () {
    if (!this.#context.hasPort) {
      return ''
    }

    return String(this.#context.port)
  }

  get path () {
    if (!this.#context.hasPath) {
      return ''
    }

    let pathEnd = this.#context.href.length

    if (this.#context.hasQuery) {
      pathEnd = this.#context.queryStart
    } else if (this.#context.hasFragment) {
      pathEnd = this.#context.fragmentStart
    }

    return this.#context.href.slice(this.#context.pathStart, pathEnd)
  }

  get query () {
    if (!this.#context.hasQuery) {
      return ''
    }

    let queryEnd = this.#context.href.length

    if (this.#context.hasFragment) {
      queryEnd = this.#context.fragmentStart
    }

    return this.#context.href.slice(this.#context.queryStart, queryEnd)
  }

  get fragment () {
    if (!this.#context.hasFragment) {
      return ''
    }

    return this.#context.href.slice(this.#context.fragmentStart)
  }

  get reference () {
    return this.#reference
  }

  [Symbol.for('nodejs.util.inspect.custom')] () {
    let res = this.constructor.name + ' {\n'
    res += `  reference: \x1b[32m'${this.reference}'\x1b[0m,\n`
    res += `  scheme: \x1b[32m'${this.scheme}'\x1b[0m,\n`
    res += `  userinfo: \x1b[32m'${this.userinfo}'\x1b[0m,\n`
    res += `  host: \x1b[32m'${this.host}'\x1b[0m,\n`
    res += `  port: \x1b[32m'${this.port}'\x1b[0m,\n`
    res += `  path: \x1b[32m'${this.path}'\x1b[0m,\n`
    res += `  query: \x1b[32m'${this.query}'\x1b[0m,\n`
    res += `  fragment: \x1b[32m'${this.fragment}'\x1b[0m\n`
    return res + '}'
  }

  toString () {
    return this.#context.href
  }
}
