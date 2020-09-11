const t = require('tap')
const Vuln = require('../lib/vuln.js')
const advisories = require('./fixtures/advisories/index.js')
const packuments = require('./fixtures/packuments/index.js')
const semver = require('semver')
const so = { includePrerelease: true }

t.test('create vulns from advisory', t => {
  const v = new Vuln('semver', advisories.semver)
  t.match(v, {
    constructor: Vuln,
    source: 31,
    name: 'semver',
    title: 'Regular Expression Denial of Service',
    severity: 'moderate',
    versions: [],
    vulnerableVersions: [],
    url: 'https://npmjs.com/advisories/31',
    range: '<4.3.2',
    id: 'jETG9IyfV60PqVhvt3BAecPdQKL2CvXOXr1GeFeSsTkGn8YHi+dU93h8zcjK/xptcxeaYeUBBKmD83eafSecwA==',
    dependency: 'semver',
    updated: false,
  }, 'vuln from advisory')

  // load without a cache entry
  v.load({}, packuments.semver)
  t.match(v, {
    constructor: Vuln,
    source: 31,
    name: 'semver',
    title: 'Regular Expression Denial of Service',
    severity: 'moderate',
    versions: semver.sort(Object.keys(packuments.semver.versions)),
    vulnerableVersions: semver.sort(Object.keys(packuments.semver.versions).filter(v =>
      semver.satisfies(v, '<4.3.2', so))),
    url: 'https://npmjs.com/advisories/31',
    range: '<4.3.2',
    id: 'jETG9IyfV60PqVhvt3BAecPdQKL2CvXOXr1GeFeSsTkGn8YHi+dU93h8zcjK/xptcxeaYeUBBKmD83eafSecwA==',
    dependency: 'semver',
    updated: true,
    packument: packuments.semver,
  }, 'updated from what was in the cache')

  const cached = JSON.parse(JSON.stringify(v))
  t.match(cached, v, 'cached copy matches the vuln')

  const vFromCache = new Vuln('semver', advisories.semver)
  vFromCache.load(cached, packuments.semver)

  t.match(vFromCache, {
    constructor: Vuln,
    source: 31,
    name: 'semver',
    title: 'Regular Expression Denial of Service',
    severity: 'moderate',
    versions: semver.sort(Object.keys(packuments.semver.versions)),
    vulnerableVersions: semver.sort(Object.keys(packuments.semver.versions).filter(v =>
      semver.satisfies(v, '<4.3.2', so))),
    url: 'https://npmjs.com/advisories/31',
    range: '<4.3.2',
    id: 'jETG9IyfV60PqVhvt3BAecPdQKL2CvXOXr1GeFeSsTkGn8YHi+dU93h8zcjK/xptcxeaYeUBBKmD83eafSecwA==',
    dependency: 'semver',
    updated: false,
    packument: packuments.semver,
  }, 'not updated from what was in the cache')

  const mv = new Vuln('pacote', v)
  t.match(mv, {
    source: 'jETG9IyfV60PqVhvt3BAecPdQKL2CvXOXr1GeFeSsTkGn8YHi+dU93h8zcjK/xptcxeaYeUBBKmD83eafSecwA==',
    name: 'pacote',
    dependency: 'semver',
    title: 'Depends on vulnerable versions of semver',
    url: null,
    severity: 'moderate',
    versions: [],
    vulnerableVersions: [],
    range: null,
    id: 'gJzFN5q57zHrhqiRn+lNQXirLlMUtC+8bFqEBGqE3XW/5VC880QTk2o/iRXUfJPT+jhc90QD+d9QIADI68nYlg==',
    updated: false,
  }, 'initial state')

  mv.load({}, packuments.pacote)
  t.match(mv, {
    source: 'jETG9IyfV60PqVhvt3BAecPdQKL2CvXOXr1GeFeSsTkGn8YHi+dU93h8zcjK/xptcxeaYeUBBKmD83eafSecwA==',
    name: 'pacote',
    dependency: 'semver',
    title: 'Depends on vulnerable versions of semver',
    url: null,
    severity: 'moderate',
    versions: semver.sort(Object.keys(packuments.pacote.versions)),
    vulnerableVersions: [],
    range: '<0.0.0-0',
    id: 'gJzFN5q57zHrhqiRn+lNQXirLlMUtC+8bFqEBGqE3XW/5VC880QTk2o/iRXUfJPT+jhc90QD+d9QIADI68nYlg==',
    updated: true,
    packument: packuments.pacote,
  }, 'loaded with empty cache')

  const mvCached = JSON.parse(JSON.stringify(mv))
  const mvFromCache = new Vuln('pacote', vFromCache)
  mvFromCache.load(mvCached, packuments.pacote)
  t.match(mvFromCache, {
    source: 'jETG9IyfV60PqVhvt3BAecPdQKL2CvXOXr1GeFeSsTkGn8YHi+dU93h8zcjK/xptcxeaYeUBBKmD83eafSecwA==',
    name: 'pacote',
    dependency: 'semver',
    title: 'Depends on vulnerable versions of semver',
    url: null,
    severity: 'moderate',
    versions: semver.sort(Object.keys(packuments.pacote.versions)),
    vulnerableVersions: [],
    range: '<0.0.0-0',
    id: 'gJzFN5q57zHrhqiRn+lNQXirLlMUtC+8bFqEBGqE3XW/5VC880QTk2o/iRXUfJPT+jhc90QD+d9QIADI68nYlg==',
    updated: false,
    packument: packuments.pacote,
  }, 'loaded from full cache')

  const mvFromCacheUpdatedSource = new Vuln('pacote', v)
  mvFromCacheUpdatedSource.load(mvCached, packuments.pacote)
  t.match(mvFromCacheUpdatedSource, {
    source: 'jETG9IyfV60PqVhvt3BAecPdQKL2CvXOXr1GeFeSsTkGn8YHi+dU93h8zcjK/xptcxeaYeUBBKmD83eafSecwA==',
    name: 'pacote',
    dependency: 'semver',
    title: 'Depends on vulnerable versions of semver',
    url: null,
    severity: 'moderate',
    versions: semver.sort(Object.keys(packuments.pacote.versions)),
    vulnerableVersions: [],
    range: '<0.0.0-0',
    id: 'gJzFN5q57zHrhqiRn+lNQXirLlMUtC+8bFqEBGqE3XW/5VC880QTk2o/iRXUfJPT+jhc90QD+d9QIADI68nYlg==',
    updated: true,
    packument: packuments.pacote,
  }, 'loaded from full cache with an advisory that was updated or not cached')

  const minimistVuln = new Vuln('minimist', advisories.minimist)
  minimistVuln.load({}, packuments.minimist)
  const mkdirpVuln = new Vuln('mkdirp', minimistVuln)
  mkdirpVuln.load({}, packuments.mkdirp)
  t.match(mkdirpVuln, {
    source: '8MDgP3O3yM8t8dcQHSMUtmH4UKJrKhWmsmV44L4YChIzoahEo+G6j24b+4BPItZck5h5zQFPFD39kOC/789lfA==',
    name: 'mkdirp',
    dependency: 'minimist',
    title: 'Depends on vulnerable versions of minimist',
    url: null,
    severity: 'low',
    versions: semver.sort(Object.keys(packuments.mkdirp.versions)),
    vulnerableVersions: ['0.4.1','0.4.2','0.5.0','0.5.1'],
    range: '0.4.1 - 0.5.1',
    id: 'dOqvv9Jcyhu8PueSJZB+eZ0G/JI7mVomMmOBSku5SA7OScjvKmHq9jcLVFKmH1wsW2LcZATEOArlMxt/fa5LmA==',
    updated: true,
  }, 'metavuln that has some vulnerable versions')
  const miniFromCache = new Vuln('minimist', advisories.minimist)
  miniFromCache.load(JSON.parse(JSON.stringify(minimistVuln)), packuments.minimist)

  // make a version of mkdirp that depends on an impossible version of minimist
  packuments.mkdirp.versions['99.99.99'] = {
    name: 'mkdirp',
    version: '99.99.99',
    dependencies: { minimist: '99.99.99' },
  }
  const mkdirpVulnBorked = new Vuln('mkdirp', miniFromCache)
  // this also covers the case when we load an otherwise cacheable
  // vuln from cache, but the packument has new versions to check.
  mkdirpVulnBorked.load(JSON.parse(JSON.stringify(mkdirpVuln)), packuments.mkdirp)
  t.match(mkdirpVulnBorked, {
    source: '8MDgP3O3yM8t8dcQHSMUtmH4UKJrKhWmsmV44L4YChIzoahEo+G6j24b+4BPItZck5h5zQFPFD39kOC/789lfA==',
    name: 'mkdirp',
    dependency: 'minimist',
    title: 'Depends on vulnerable versions of minimist',
    url: null,
    severity: 'low',
    versions: semver.sort(Object.keys(packuments.mkdirp.versions)),
    vulnerableVersions: ['0.4.1','0.4.2','0.5.0','0.5.1','99.99.99'],
    range: '0.4.1 - 0.5.1 || >=99.99.99',
    id: 'dOqvv9Jcyhu8PueSJZB+eZ0G/JI7mVomMmOBSku5SA7OScjvKmHq9jcLVFKmH1wsW2LcZATEOArlMxt/fa5LmA==',
    updated: true,
  }, 'impossible to resolve versions are also treated as vulnerabilities to avoid')

  // a version of mkdirp that bundles a potentially vulnerable minimist
  packuments.mkdirp.versions['0.5.0-bundler'] = {
    name: 'mkdirp',
    version: '0.5.0-bundler',
    bundleDependencies: ['minimist'],
    dependencies: { minimist: '' },
  }
  const mkdirpVulnBundled = new Vuln('mkdirp', minimistVuln)
  mkdirpVulnBundled.load(JSON.parse(JSON.stringify(mkdirpVuln)), packuments.mkdirp)
  t.match(mkdirpVulnBundled, {
    source: '8MDgP3O3yM8t8dcQHSMUtmH4UKJrKhWmsmV44L4YChIzoahEo+G6j24b+4BPItZck5h5zQFPFD39kOC/789lfA==',
    name: 'mkdirp',
    dependency: 'minimist',
    title: 'Depends on vulnerable versions of minimist',
    url: null,
    severity: 'low',
    versions: semver.sort(Object.keys(packuments.mkdirp.versions)),
    vulnerableVersions: ['0.4.1','0.4.2','0.5.0-bundler','0.5.0','0.5.1','99.99.99'],
    range: '0.4.1 - 0.5.1 || >=99.99.99',
    id: 'dOqvv9Jcyhu8PueSJZB+eZ0G/JI7mVomMmOBSku5SA7OScjvKmHq9jcLVFKmH1wsW2LcZATEOArlMxt/fa5LmA==',
    updated: true,
  }, 'bundled deps are vulnerable if intersecting range')

  t.notOk(mkdirpVulnBundled.testVersion('1234.1234.1234'),
    'missing version is not treated as vulnerable')
  t.ok(mkdirpVulnBundled.testVersion('0.5.0'),
    'known vulnerable version is shown as vulnerable')

  // ok now remove the weird versions, like they were unpublished
  delete packuments.mkdirp.versions['0.5.0-bundler']
  delete packuments.mkdirp.versions['99.99.99']
  const mkdirpVulnRmVers = new Vuln('mkdirp', miniFromCache)
  mkdirpVulnRmVers.load(JSON.parse(JSON.stringify(mkdirpVulnBundled)), packuments.mkdirp)
  console.error(mkdirpVulnRmVers.vulnerableVersions)
  t.match(mkdirpVulnRmVers, {
    source: '8MDgP3O3yM8t8dcQHSMUtmH4UKJrKhWmsmV44L4YChIzoahEo+G6j24b+4BPItZck5h5zQFPFD39kOC/789lfA==',
    name: 'mkdirp',
    dependency: 'minimist',
    title: 'Depends on vulnerable versions of minimist',
    url: null,
    severity: 'low',
    versions: semver.sort(Object.keys(packuments.mkdirp.versions)),
    vulnerableVersions: ['0.4.1','0.4.2','0.5.0','0.5.1'],
    range: '0.4.1 - 0.5.1',
    id: 'dOqvv9Jcyhu8PueSJZB+eZ0G/JI7mVomMmOBSku5SA7OScjvKmHq9jcLVFKmH1wsW2LcZATEOArlMxt/fa5LmA==',
    updated: true,
  }, 'updated to remove versions that were in cache but not packument')

  // test invalid loads
  t.throws(() => mkdirpVuln.load(null, {}), {
    message: 'invalid cached data, expected object',
  })
  t.throws(() => mkdirpVuln.load({}, null), {
    message: 'invalid packument data, expected object',
  })
  t.throws(() => mkdirpVuln.load({ id: 'wrong' }, {}), {
    message: 'loading from incorrect cache entry',
    expected: mkdirpVuln.id,
    actual: 'wrong',
  })
  t.throws(() => mkdirpVuln.load({}, packuments.minimist), {
    message: 'loading from incorrect packument',
    expected: 'mkdirp',
    actual: 'minimist',
  })


  t.end()
})
