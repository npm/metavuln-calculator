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
const _cached = Symbol('cached')
class Calculator {
  constructor (options = {}) {
    this.options = { ...options }
    this.cache = this.options.cache || (homedir() + '/.npm/_cacache')
    this.options.cache = this.cache
    this.packuments = new Map()
    this.cached = new Map()
  }

  async calculate (name, source) {
    process.emit('time', 'metavuln:calculate')
    const vuln = new Vuln(name, source, this.options)
    // load packument and cached vuln
    const [cached, packument] = await Promise.all([
      this[_cached](vuln),
      this[_packument](name)
    ])
    vuln.load(cached, packument)
    this.cached.set(vuln.id, vuln)
    if (vuln.updated)
      await this[_cachePut](vuln)
    process.emit('timeEnd', 'metavuln:calculate')
    return vuln
  }

  async [_cachePut] (vuln) {
    process.emit('time', 'metavuln:cache:put')
    const data = JSON.stringify(vuln)
    const options = { ...this.options }
    await cacache.put(this.cache, vuln.id, data, options).catch(() => {})
    process.emit('timeEnd', 'metavuln:cache:put')
  }

  async [_cached] (vuln) {
    const { id } = vuln
    if (this.cached.has(id))
      return this.cached.get(id)

    process.emit('time', `metavuln:cache:read:${id}`)
    const p = cacache.get(this.cache, id, { ...this.options })
      .catch(() => ({ data: '{}' }))
      .then(({ data }) => {
        data = jsonParse(data)
        process.emit('timeEnd', `metavuln:cache:read:${id}`)
        this.cached.set(id, data)
        return data
      })
    this.cached.set(id, p)
    return p
  }

  async [_packument] (name) {
    if (this.packuments.has(name))
      return this.packuments.get(name)

    process.emit('time', `metavuln:packument:${name}`)
    const p = pacote.packument(name, { ...this.options })
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
        this.packuments.set(name, paku)
        return paku
      })
    this.packuments.set(name, p)
    return p
  }
}

module.exports = Calculator
