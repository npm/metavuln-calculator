const { readdirSync } = require('fs')
const { basename } = require('path')
for (const f of readdirSync(__dirname).filter(s => /\.json$/.test(s))) {
  exports[basename(f, '.json')] = require(`./${f}`)
}
