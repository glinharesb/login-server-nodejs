import Crypto from './Crypto'

export class OutputMessage {
  private buffer: Buffer = Buffer.allocUnsafe(8192)
  private header: number = 10
  private pos: number = this.header

  private check(size: number) {
    if (this.pos + size > this.buffer.length) {
      throw `Packet overflow (size: ${this.buffer.length})`
    }
  }

  length(): number {
    return this.pos
  }

  getSendBuffer(): Buffer {
    return Buffer.from(this.buffer.buffer, this.header, this.pos - this.header)
  }

  addU8(value: number) {
    this.check(1)

    this.buffer.writeUInt8(value, this.pos)
    this.pos += 1
  }

  addU16(value: number) {
    this.check(2)

    this.buffer.writeUInt16LE(value, this.pos)
    this.pos += 2
  }

  addU32(value: number) {
    this.check(4)

    this.buffer.writeUInt32LE(value, this.pos)
    this.pos += 4
  }

  addString(value: string) {
    this.check(value.length + 2)

    this.addU16(value.length)
    this.buffer.write(value, this.pos)
    this.pos += value.length
  }

  addBytes(value: Buffer) {
    this.check(value.length + 2)

    this.addU16(value.length)
    value.copy(this.buffer, this.pos)
    this.pos += value.length
  }

  xteaEncrypt(xtea: number[]) {
    // add size
    this.buffer.writeUInt16LE(this.pos - this.header, this.header - 2)
    this.header -= 2

    // fill
    if ((this.pos - this.header) % 8 !== 0) {
      const toAdd = 8 - ((this.pos - this.header) % 8)
      for (let i = 0; i < toAdd; ++i) {
        this.addU8(0x33)
      }
    }

    // xtea encrypt
    if (this.header !== 8) {
      // must have 8 reserved bytes
      throw `Invalid header size: ${this.header}`
    }

    Crypto.xteaEncrypt(this.buffer, this.pos, xtea)
  }

  addChecksum() {
    this.buffer.writeUInt32LE(
      Crypto.adler32(this.buffer, this.header, this.pos - this.header),
      this.header - 4
    )

    this.header -= 4
  }

  addSize() {
    this.buffer.writeUInt16LE(this.pos - this.header, this.header - 2)
    this.header -= 2
  }
}
