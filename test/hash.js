const t = require('tap')
const hash = require('../lib/hash.js')

t.equal(
  hash({ name: 'name', source: 'string' }),
  'H5g4PQXxK9hZai4+htDRkAmOHMHwtnFkWPhtKeqzj6+4h04Ydn8BTmtdGdlHNQYC1lJalvPtlsCpZU+iJyNATQ==')
t.equal(
  hash({ name: 'number', source: 123 }),
  'ogXIWvAyjuIKtDbQmQD29hgUJackr36y6oWohHLx2hLqnhzNSQBhq/a5sjH6myWL/s5Yu2IlUcowvNZjciFwoQ==')

t.equal(hash({ name: 'x', source: 'y' }), hash({ source: 'y', name: 'x' }),
  'not order dependent')
t.equal(hash({ name: 'x', source: 123 }), hash({ source: 123, name: 'x' }),
  'not order dependent')

t.not(hash({ name: 'x', source: 123 }), hash({ name: 'x', source: '123' }),
  'different hashes for different source types')
