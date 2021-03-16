const t = require('tap')
const getDepSpec = require('../lib/get-dep-spec.js')

t.equal(getDepSpec({ dependencies: { dep: '1' } }, 'dep'), '1')
t.equal(getDepSpec({ optionalDependencies: { dep: '1' } }, 'dep'), '1')
t.equal(getDepSpec({ peerDependencies: { dep: '1' } }, 'dep'), '1')
t.equal(getDepSpec({
  dependencies: { dep: '1' },
  optionalDependencies: { dep: '2' },
}, 'dep'), '1', 'prefer prod deps over optional')
t.equal(getDepSpec({
  dependencies: { dep: '1' },
  peerDependencies: { dep: '2' },
}, 'dep'), '1', 'prefer prod deps over peer')
t.equal(getDepSpec({
  optionalDependencies: { dep: '1' },
  peerDependencies: { dep: '2' },
}, 'dep'), '1', 'prefer optional deps over peer')
t.equal(getDepSpec({ devDependencies: { dep: '1' } }, 'dep'), null,
  'ignore dev')
t.equal(getDepSpec({
  dependencies: null,
  optionalDependencies: null,
  peerDependencies: null
}, 'dep'), null, 'ignore null fields')
