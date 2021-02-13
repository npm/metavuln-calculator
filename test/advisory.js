const t = require('tap')
const Advisory = require('../lib/advisory.js')
const advisories = require('./fixtures/advisories/index.js')
const packuments = require('./fixtures/packuments/index.js')
const semver = require('semver')
const so = { includePrerelease: true }

t.test('create vulns from advisory', t => {
  const v = new Advisory('semver', advisories.semver)
  t.match(v, {
    constructor: Advisory,
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
  }, 'from raw advisory')

  // load without a cache entry
  v.load({}, packuments.semver)
  t.match(v, {
    constructor: Advisory,
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
  t.match(cached, v, 'cached copy matches the advisory')

  const vFromCache = new Advisory('semver', advisories.semver)
  vFromCache.load(cached, packuments.semver)

  t.match(vFromCache, {
    constructor: Advisory,
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

  const mv = new Advisory('pacote', v)
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
  const mvFromCache = new Advisory('pacote', vFromCache)
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

  const mvFromCacheUpdatedSource = new Advisory('pacote', v)
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

  const minimistVuln = new Advisory('minimist', advisories.minimist)
  minimistVuln.load({}, packuments.minimist)
  const mkdirpVuln = new Advisory('mkdirp', minimistVuln)
  mkdirpVuln.load({}, packuments.mkdirp)
  t.match(mkdirpVuln, {
    source: '8MDgP3O3yM8t8dcQHSMUtmH4UKJrKhWmsmV44L4YChIzoahEo+G6j24b+4BPItZck5h5zQFPFD39kOC/789lfA==',
    name: 'mkdirp',
    dependency: 'minimist',
    title: 'Depends on vulnerable versions of minimist',
    url: null,
    severity: 'low',
    versions: semver.sort(Object.keys(packuments.mkdirp.versions)),
    vulnerableVersions: ['0.4.1', '0.4.2', '0.5.0', '0.5.1'],
    range: '0.4.1 - 0.5.1',
    id: 'dOqvv9Jcyhu8PueSJZB+eZ0G/JI7mVomMmOBSku5SA7OScjvKmHq9jcLVFKmH1wsW2LcZATEOArlMxt/fa5LmA==',
    updated: true,
  }, 'metavuln that has some vulnerable versions')
  const miniFromCache = new Advisory('minimist', advisories.minimist)
  miniFromCache.load(JSON.parse(JSON.stringify(minimistVuln)), packuments.minimist)

  // make a version of mkdirp that depends on an impossible version of minimist
  packuments.mkdirp.versions['99.99.99'] = {
    name: 'mkdirp',
    version: '99.99.99',
    dependencies: { minimist: '99.99.99' },
  }
  const mkdirpVulnBorked = new Advisory('mkdirp', miniFromCache)
  // this also covers the case when we load an otherwise cacheable
  // advisory from cache, but the packument has new versions to check.
  mkdirpVulnBorked.load(JSON.parse(JSON.stringify(mkdirpVuln)), packuments.mkdirp)
  t.match(mkdirpVulnBorked, {
    source: '8MDgP3O3yM8t8dcQHSMUtmH4UKJrKhWmsmV44L4YChIzoahEo+G6j24b+4BPItZck5h5zQFPFD39kOC/789lfA==',
    name: 'mkdirp',
    dependency: 'minimist',
    title: 'Depends on vulnerable versions of minimist',
    url: null,
    severity: 'low',
    versions: semver.sort(Object.keys(packuments.mkdirp.versions)),
    vulnerableVersions: ['0.4.1', '0.4.2', '0.5.0', '0.5.1', '99.99.99'],
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
  const mkdirpVulnBundled = new Advisory('mkdirp', minimistVuln)
  mkdirpVulnBundled.load(JSON.parse(JSON.stringify(mkdirpVuln)), packuments.mkdirp)
  t.match(mkdirpVulnBundled, {
    source: '8MDgP3O3yM8t8dcQHSMUtmH4UKJrKhWmsmV44L4YChIzoahEo+G6j24b+4BPItZck5h5zQFPFD39kOC/789lfA==',
    name: 'mkdirp',
    dependency: 'minimist',
    title: 'Depends on vulnerable versions of minimist',
    url: null,
    severity: 'low',
    versions: semver.sort(Object.keys(packuments.mkdirp.versions)),
    vulnerableVersions: ['0.4.1', '0.4.2', '0.5.0-bundler', '0.5.0', '0.5.1', '99.99.99'],
    range: '0.4.1 - 0.5.1 || >=99.99.99',
    id: 'dOqvv9Jcyhu8PueSJZB+eZ0G/JI7mVomMmOBSku5SA7OScjvKmHq9jcLVFKmH1wsW2LcZATEOArlMxt/fa5LmA==',
    updated: true,
  }, 'bundled deps are vulnerable if intersecting range')

  t.notOk(mkdirpVulnBundled.testVersion('1234.1234.1234'),
    'missing version is not treated as vulnerable')
  t.ok(mkdirpVulnBundled.testVersion('1234.1234.1235', '0.0.8'),
    'missing version with spec is treated as vulnerable based on spec')
  t.ok(mkdirpVulnBundled.testVersion('1234.1234.1236', 'github:foo/bar'),
    'missing version with git spec is treated as vulnerable always')
  t.ok(mkdirpVulnBundled.testVersion('0.5.0'),
    'known vulnerable version is shown as vulnerable')

  // ok now remove the weird versions, like they were unpublished
  delete packuments.mkdirp.versions['0.5.0-bundler']
  delete packuments.mkdirp.versions['99.99.99']
  const mkdirpVulnRmVers = new Advisory('mkdirp', miniFromCache)
  mkdirpVulnRmVers.load(JSON.parse(JSON.stringify(mkdirpVulnBundled)), packuments.mkdirp)
  t.match(mkdirpVulnRmVers, {
    source: '8MDgP3O3yM8t8dcQHSMUtmH4UKJrKhWmsmV44L4YChIzoahEo+G6j24b+4BPItZck5h5zQFPFD39kOC/789lfA==',
    name: 'mkdirp',
    dependency: 'minimist',
    title: 'Depends on vulnerable versions of minimist',
    url: null,
    severity: 'low',
    versions: semver.sort(Object.keys(packuments.mkdirp.versions)),
    vulnerableVersions: ['0.4.1', '0.4.2', '0.5.0', '0.5.1'],
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
  t.throws(() => mkdirpVuln.load({}, mkdirpVuln.packument), {
    message: 'advisory object already loaded',
  })

  t.end()
})

t.test('load with empty packument', t => {
  const v = new Advisory('semver', advisories.semver)
  v.load({}, {name: 'semver', versions: {}})
  t.match(v, {
    constructor: Advisory,
    source: 31,
    name: 'semver',
    dependency: 'semver',
    title: 'Regular Expression Denial of Service',
    url: 'https://npmjs.com/advisories/31',
    severity: 'moderate',
    versions: [],
    vulnerableVersions: [],
    range: '<4.3.2',
    id: 'jETG9IyfV60PqVhvt3BAecPdQKL2CvXOXr1GeFeSsTkGn8YHi+dU93h8zcjK/xptcxeaYeUBBKmD83eafSecwA==',
  })

  t.ok(v.testVersion('4.3.1'), 'version covered by range is vulnerable')
  t.match(v, { vulnerableVersions: ['4.3.1'], versions: [] }, 'added to set')
  t.end()
})

t.test('a package with a lot of prerelease versions', t => {
  const a = advisories['graphql-codegen-plugin-helpers']
  const v = new Advisory('@graphql-codegen/plugin-helpers', a)
  v.load({}, packuments['graphql-codegen-plugin-helpers'])
  const meta = new Advisory('@graphql-codegen/visitor-plugin-common', v)
  meta.load({}, packuments['graphql-codegen-visitor-plugin-common'])
  // kinda weird range here because git tags don't sort alphabetically lol
  t.equal(meta.range, '<=1.17.8-alpha-f79b3113.0 || 1.17.13-alpha-7d3e78ce.0')
  t.end()
})

t.test('a package with only prerelease versions', t => {
  const a = {
    id: 1234567890,
    url: 'https://npmjs.com/advisories/1234567890',
    title: 'lol yolo idfk whatever bbq',
    vulnerable_versions: '<=0.0.0-pre.5',
    severity: 'low',
  }
  const v = new Advisory('foo', a)
  v.load({}, {
    name: 'foo',
    'dist-tags': { latest: '0.0.0-pre.7' },
    versions: {
      '0.0.0-pre.1': {},
      '0.0.0-pre.2': {},
      '0.0.0-pre.3': {},
      '0.0.0-pre.4': {},
      '0.0.0-pre.5': {},
      '0.0.0-pre.6': {},
      '0.0.0-pre.7': {},
    },
  })
  const meta = new Advisory('bar', v)
  meta.load({}, {
    name: 'bar',
    'dist-tags': { latest: '0.0.0-pre.7' },
    versions: {
      '0.0.0-pre.1': { dependencies: { foo: '0.0.0-pre.1' }},
      '0.0.0-pre.2': { dependencies: { foo: '0.0.0-pre.2' }},
      '0.0.0-pre.3': { dependencies: { foo: '0.0.0-pre.3' }},
      '0.0.0-pre.4': { dependencies: { foo: '0.0.0-pre.4' }},
      '0.0.0-pre.5': { dependencies: { foo: '0.0.0-pre.5' }},
      '0.0.0-pre.6': { dependencies: { foo: '0.0.0-pre.6' }},
      '0.0.0-pre.7': { dependencies: { foo: '0.0.0-pre.7' }},
    },
  })
  t.equal(meta.range, '<=0.0.0-pre.5')
  t.end()
})

