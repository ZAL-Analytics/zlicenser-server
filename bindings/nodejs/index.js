'use strict'

const { existsSync } = require('fs')
const { join } = require('path')

const { platform, arch } = process

const platformMap = {
  'linux-x64': 'index.linux-x64-gnu.node',
  'linux-arm64': 'index.linux-arm64-gnu.node',
  'darwin-x64': 'index.darwin-x64.node',
  'darwin-arm64': 'index.darwin-arm64.node',
  'win32-x64': 'index.win32-x64-msvc.node',
}

const key = `${platform}-${arch}`
const localFile = platformMap[key]

if (!localFile) {
  throw new Error(`Unsupported platform: ${platform}-${arch}`)
}

const localPath = join(__dirname, localFile)

if (!existsSync(localPath)) {
  throw new Error(`Native binding not found: ${localPath}. Run 'npm run build' first.`)
}

module.exports = require(localPath)
