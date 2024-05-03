const t = require('tap')
const requireInject = require('require-inject')
const packuments = require('./fixtures/packuments/index.js')
const advisories = require('./fixtures/advisories/index.js')
const pacote = {
  packument: async (name) => {
    if (packuments[name]) {
      return packuments[name]
    }
    throw Object.assign(new Error('not found'), {
      code: 'E404',
    })
  },
}
const cacache = require('cacache')
const Advisory = require('../lib/advisory.js')

const cache = t.testdir()

const Calculator = requireInject('../lib/index.js', { pacote })

t.test('basic instantiation', t => {
  const defaults = new Calculator()
  t.equal(defaults.cache, require('os').homedir() + '/.npm/_cacache')
  t.strictSame(defaults.options, { cache: defaults.cache })
  const calc = new Calculator({ cache })
  t.strictSame(calc.options, { cache })
  t.equal(calc.cache, cache)
  t.end()
})

t.test('calculate fresh', async t => {
  const calc = new Calculator({ cache })
  const minimistFresh = await calc.calculate('minimist', advisories.minimist)
  t.match(minimistFresh, {
    constructor: Advisory,
    updated: true,
    source: 1179,
    name: 'minimist',
    dependency: 'minimist',
    type: 'advisory',
    range: '<0.2.1 || >=1.0.0 <1.2.3',
    id: '8MDgP3O3yM8t8dcQHSMUtmH4UKJrKhWmsmV44L4YChIzoahEo+G6j24b+4BPItZck5h5zQFPFD39kOC/789lfA==',
  })
  // calculate another one for same package to hit the packument memoizing
  const otherMinimistAdvisory = {
    ...advisories.minimist,
    id: 123456,
  }
  const otherMinimistVuln = await calc.calculate('minimist', otherMinimistAdvisory)
  t.match(otherMinimistVuln, {
    constructor: Advisory,
    source: 123456,
    name: 'minimist',
    dependency: 'minimist',
    type: 'advisory',
    range: '<0.2.1 || >=1.0.0 <1.2.3',
    id: 'WNi+Ammra045Ltb3M04AEe31yaYdjqUffX/iwhuagBKRTyZCzaNihh0prxpc4kVhVK6wXV1XDSXTGEqt1JusCA==',
    updated: true,
  })

  const mkdirpFresh = await calc.calculate('mkdirp', minimistFresh)
  t.match(mkdirpFresh, {
    constructor: Advisory,
    type: 'metavuln',
    source: minimistFresh.id,
    name: 'mkdirp',
    dependency: 'minimist',
    title: 'Depends on vulnerable versions of minimist',
    url: null,
    severity: minimistFresh.severity,
    range: '0.4.1 - 0.5.1',
    id: 'dOqvv9Jcyhu8PueSJZB+eZ0G/JI7mVomMmOBSku5SA7OScjvKmHq9jcLVFKmH1wsW2LcZATEOArlMxt/fa5LmA==',
    updated: true,
  })
})

t.test('handle cache failures', async t => {
  const { get, put } = cacache
  t.teardown(() => Object.assign(cacache, { get, put }))
  cacache.get = async () => {
    throw new Error('nope')
  }
  cacache.put = async () => {
    throw new Error('nope')
  }

  const calc = new Calculator({ cache })
  const minimistFresh = await calc.calculate('minimist', advisories.minimist)
  t.match(minimistFresh, {
    constructor: Advisory,
    source: 1179,
    name: 'minimist',
    dependency: 'minimist',
    type: 'advisory',
    range: '<0.2.1 || >=1.0.0 <1.2.3',
    id: '8MDgP3O3yM8t8dcQHSMUtmH4UKJrKhWmsmV44L4YChIzoahEo+G6j24b+4BPItZck5h5zQFPFD39kOC/789lfA==',
    updated: true, // <-- "updated" because cache read failed
  })
  await calc.calculate('mkdirp', minimistFresh)
})

t.test('calculate from cache', async t => {
  const calc = new Calculator({ cache })
  const minimistCached = await calc.calculate('minimist', advisories.minimist)
  t.match(minimistCached, {
    constructor: Advisory,
    updated: false,
    source: 1179,
    name: 'minimist',
    dependency: 'minimist',
    type: 'advisory',
    range: '<0.2.1 || >=1.0.0 <1.2.3',
    id: '8MDgP3O3yM8t8dcQHSMUtmH4UKJrKhWmsmV44L4YChIzoahEo+G6j24b+4BPItZck5h5zQFPFD39kOC/789lfA==',
  })
  const mkdirpCached = await calc.calculate('mkdirp', minimistCached)
  t.match(mkdirpCached, {
    constructor: Advisory,
    type: 'metavuln',
    source: minimistCached.id,
    name: 'mkdirp',
    dependency: 'minimist',
    title: 'Depends on vulnerable versions of minimist',
    url: null,
    severity: minimistCached.severity,
    range: '0.4.1 - 0.5.1',
    id: 'dOqvv9Jcyhu8PueSJZB+eZ0G/JI7mVomMmOBSku5SA7OScjvKmHq9jcLVFKmH1wsW2LcZATEOArlMxt/fa5LmA==',
    updated: false,
  })
  const mkdirpCached2 = await calc.calculate('mkdirp', minimistCached)
  t.equal(mkdirpCached.packument, mkdirpCached2.packument,
    'reuse packument rather than make an extra request')
})

t.test('packument not found', async t => {
  const calc = new Calculator({ cache })
  const notSemver = await calc.calculate('not-semver', advisories.semver)
  t.match(notSemver, {
    source: 31,
    name: 'not-semver',
    dependency: 'not-semver',
    title: 'Regular Expression Denial of Service',
    url: 'https://npmjs.com/advisories/31',
    severity: 'moderate',
    versions: [],
    vulnerableVersions: [],
    range: '<4.3.2',
    id: 'TEayTAF88mYJ/wy04iwwifoEUL/+mmrrYoE4EbGSe7s9nbZ8+zQQVqwnhh1TwzEFwV/DoaVAjHTdt+GXvT04lg==',
  })
})
