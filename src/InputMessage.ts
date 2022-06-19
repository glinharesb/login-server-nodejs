import Crypto from './Crypto'

export class InputMessage {
  private buffer: Buffer
  private pos: number

  constructor(buffer: Buffer) {
    this.buffer = buffer
    this.pos = 0
  }

  check(size: number) {
    if (this.pos + size > this.buffer.length) {
      throw `Packet overflow (size: ${this.buffer.length})`
    }
  }

  getU8() {
    this.check(1)

    const ret = this.buffer.readUInt8(this.pos)
    this.pos += 1

    return ret
  }

  peekU8() {
    this.check(1)

    const ret = this.buffer.readUInt8(this.pos)
    return ret
  }

  getU16() {
    this.check(2)

    const ret = this.buffer.readUInt16LE(this.pos)
    this.pos += 2

    return ret
  }

  peekU16() {
    this.check(2)

    const ret = this.buffer.readUInt16LE(this.pos)
    return ret
  }

  getU32() {
    this.check(4)

    const ret = this.buffer.readUInt32LE(this.pos)
    this.pos += 4

    return ret
  }

  peekU32() {
    this.check(4)

    const ret = this.buffer.readUInt32LE(this.pos)

    return ret
  }

  getString(size?: number) {
    if (!size) {
      size = this.getU16()
    }

    this.check(size)

    const ret = this.buffer.toString('ascii', this.pos, this.pos + size)
    this.pos += size

    return ret
  }

  peekString(size: number) {
    if (!size) {
      size = this.getU16()
    }

    this.check(size)

    const ret = this.buffer.toString('ascii', this.pos, this.pos + size)

    return ret
  }

  getBytes(size: number) {
    this.check(size)

    const ret = this.buffer.subarray(this.pos, this.pos + size)
    this.pos += size

    return ret
  }

  adler32(): number {
    return Crypto.adler32(
      this.buffer,
      this.pos + 4,
      this.buffer.length - this.pos - 4
    )
  }

  rsaDecrypt() {
    return new InputMessage(Crypto.rsaDecrypt(this.getBytes(128)))
  }
}
