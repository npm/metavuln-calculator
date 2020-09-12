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

class Calculator {
  constructor (options = {}) {
    this[_options] = { ...options }
    this[_cache] = this[_options].cache || (homedir() + '/.npm/_cacache')
    this[_options].cache = this[_cache]
    this[_packuments] = new Map()
    this[_cacheData] = new Map()
  }

  get cache () {
    return this[_cache]
  }

  get options () {
    return { ...this[_options] }
  }

  async calculate (name, source) {
    process.emit('time', 'metavuln:calculate')
    const vuln = new Vuln(name, source, this[_options])
    // load packument and cached vuln
    const [cached, packument] = await Promise.all([
      this[_cacheGet](vuln),
      this[_packument](name)
    ])
    vuln.load(cached, packument)
    this[_cacheData].set(vuln.id, vuln)
    if (vuln.updated)
      await this[_cachePut](vuln)
    process.emit('timeEnd', 'metavuln:calculate')
    return vuln
  }

  async [_cachePut] (vuln) {
    process.emit('time', 'metavuln:cache:put')
    const data = JSON.stringify(vuln)
    const options = { ...this[_options] }
    this[_cacheData].set(vuln.id, jsonParse(data))
    await cacache.put(this[_cache], vuln.id, data, options).catch(() => {})
    process.emit('timeEnd', 'metavuln:cache:put')
  }

  async [_cacheGet] (vuln) {
    const { id } = vuln
    if (this[_cacheData].has(id))
      return this[_cacheData].get(id)

    process.emit('time', `metavuln:cache:read:${id}`)
    const p = cacache.get(this[_cache], id, { ...this[_options] })
      .catch(() => ({ data: '{}' }))
      .then(({ data }) => {
        data = jsonParse(data)
        process.emit('timeEnd', `metavuln:cache:read:${id}`)
        this[_cacheData].set(id, data)
        return data
      })
    this[_cacheData].set(id, p)
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
