// this is the public class that is used by consumers.
// the Vuln class handles all the calculation, and this
// class handles all the IO with the registry and cache.
const pacote = require('pacote')
const cacache = require('cacache')
const Vuln = require('./vuln.js')
const {homedir} = require('os')
const jsonParse = require('json-parse-even-better-errors')

const _packument = Symbol('packument')
const _cachePut = Symbol('cachePut')
const _cacheGet = Symbol('cacheGet')
const _cacheData = Symbol('cacheData')
const _packuments = Symbol('packuments')
const _cache = Symbol('cache')
const _options = Symbol('options')
const _vulns = Symbol('vulns')
const _calculate = Symbol('calculate')

class Calculator {
  constructor (options = {}) {
    this[_options] = { ...options }
    this[_cache] = this[_options].cache || (homedir() + '/.npm/_cacache')
    this[_options].cache = this[_cache]
    this[_packuments] = new Map()
    this[_cacheData] = new Map()
    this[_vulns] = new Map()
  }

  get cache () {
    return this[_cache]
  }

  get options () {
    return { ...this[_options] }
  }

  async calculate (name, source) {
    const k = `${name}:${source.id}`
    if (this[_vulns].has(k))
      return this[_vulns].get(k)

    const p = this[_calculate](name, source).then(vuln => {
      this[_vulns].set(k, vuln)
      return vuln
    })
    this[_vulns].set(k, p)
    return p
  }

  async [_calculate] (name, source) {
    const k = `${name}:${source.id}`
    const t = `metavuln:calculate:${k}`
    process.emit('time', t)
    const vuln = new Vuln(name, source, this[_options])
    // load packument and cached vuln
    const [cached, packument] = await Promise.all([
      this[_cacheGet](vuln),
      this[_packument](name)
    ])
    process.emit('time', `metavuln:load:${k}`)
    vuln.load(cached, packument)
    process.emit('timeEnd', `metavuln:load:${k}`)
    this[_cacheData].set(vuln.id, vuln)
    if (vuln.updated)
      await this[_cachePut](vuln)
    this[_vulns].set(k, vuln)
    process.emit('timeEnd', t)
    return vuln
  }

  async [_cachePut] (vuln) {
    const { name, id } = vuln
    const key = `security-advisory:${name}:${id}`
    process.emit('time', `metavuln:cache:put:${key}`)
    const data = JSON.stringify(vuln)
    const options = { ...this[_options] }
    this[_cacheData].set(key, jsonParse(data))
    await cacache.put(this[_cache], key, data, options).catch(() => {})
    process.emit('timeEnd', `metavuln:cache:put:${key}`)
  }

  async [_cacheGet] (vuln) {
    const { name, id } = vuln
    const key = `security-advisory:${name}:${id}`
    /* istanbul ignore if - should be impossible, since we memoize the
     * vuln object itself using the same key, just being cautious */
    if (this[_cacheData].has(key))
      return this[_cacheData].get(key)

    process.emit('time', `metavuln:cache:get:${key}`)
    const p = cacache.get(this[_cache], key, { ...this[_options] })
      .catch(() => ({ data: '{}' }))
      .then(({ data }) => {
        data = jsonParse(data)
        process.emit('timeEnd', `metavuln:cache:get:${key}`)
        this[_cacheData].set(key, data)
        return data
      })
    this[_cacheData].set(key, p)
    return p
  }

  async [_packument] (name) {
    if (this[_packuments].has(name))
      return this[_packuments].get(name)

    process.emit('time', `metavuln:packument:${name}`)
    const p = pacote.packument(name, { ...this[_options] })
      .catch((er) => {
        // presumably not something from the registry.
        // an empty packument will have an effective range of *
        return {
          name,
          versions: {},
        }
      })
      .then(paku => {
        process.emit('timeEnd', `metavuln:packument:${name}`)
        this[_packuments].set(name, paku)
        return paku
      })
    this[_packuments].set(name, p)
    return p
  }
}

module.exports = Calculator
