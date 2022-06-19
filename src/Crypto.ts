import crypto from 'crypto'
import constants from 'constants'
import path from 'path'
import fs from 'fs'

class Crypto {
  privateKey: string = ''
  keyFile: string = 'key.pem'

  constructor() {
    if (this.privateKey.length > 0) {
      throw `Crypto is already initialized`
    }

    try {
      const keyFilePath = path.resolve(__dirname, '..', this.keyFile)
      this.privateKey = fs.readFileSync(keyFilePath, 'utf-8').toString().trim()

      // test
      crypto.publicEncrypt(this.privateKey, Buffer.from('Test'))
    } catch (error) {
      throw `Can't load private key from ${this.keyFile}`
    }
  }

  adler32(buffer: Buffer, offset: number, size: number): number {
    const adler = 65521
    let d = new Uint32Array(2)

    d[0] = 1
    d[1] = 0

    let p = offset
    while (size > 0) {
      let tlen = size > 5552 ? 5552 : size
      size -= tlen

      while (tlen--) {
        d[0] = d[0] + buffer[p++]
        d[1] = d[1] + d[0]
      }

      d[0] = d[0] % adler
      d[1] = d[1] % adler
    }

    d[1] = (d[1] << 16) | d[0]
    return d[1]
  }

  rsaDecrypt(buffer: Buffer): Buffer {
    if (buffer.length !== 128) {
      throw `rsaDecrypt: invalid buffer length: ${buffer.length}`
    }

    return crypto.privateDecrypt(
      {
        key: this.privateKey,
        padding: constants.RSA_NO_PADDING,
        passphrase: ''
      },
      buffer
    )
  }

  xteaEncrypt = (buffer: Buffer, size: number, xtea: number[]) => {
    let u32 = new Uint32Array(
      buffer.buffer,
      buffer.byteOffset,
      size / Uint32Array.BYTES_PER_ELEMENT
    )

    for (let i = 2; i < u32.length; i += 2) {
      u32[0] = 0 // sum

      for (let j = 0; j < 32; ++j) {
        u32[i] +=
          ((((u32[i + 1] << 4) >>> 0) ^ (u32[i + 1] >>> 5)) + u32[i + 1]) ^
          (u32[0] + xtea[u32[0] & 3])

        u32[0] = (u32[0] + 0x9e3779b9) >>> 0

        u32[i + 1] +=
          ((((u32[i] << 4) >>> 0) ^ (u32[i] >>> 5)) + u32[i]) ^
          (u32[0] + xtea[(u32[0] >> 11) & 3])
      }
    }
  }
}

export default new Crypto()
