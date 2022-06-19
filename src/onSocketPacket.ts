import net from 'net'
import { InputMessage } from './InputMessage'
import { OutputMessage } from './OutputMessage'
import { CONSOLE_COLORS } from './utils'

const VERSION_MIN = 800
const VERSION_MAX = 1100

export async function onSocketPacket(socket: net.Socket, packet: InputMessage) {
  let hasCheksum = false
  const checksum = packet.peekU32()
  if (checksum === packet.adler32()) {
    packet.getU32()

    hasCheksum = true
  }

  const packetType = packet.getU8()
  // status check
  if (packetType === 0xff) {
    console.log(`status_check`)
  }

  if (packetType !== 0x01) {
    throw `Invalid packet type: ${packetType}, should be 1`
  }

  // onRecvFirstMessage start

  packet.getU16() // os

  const version = packet.getU16()
  if (version >= 980) {
    packet.getU32() // client version
  }

  if (version >= 1071) {
    packet.getU16() // content revision
    packet.getU16() // unknown, otclient sends 0
  } else {
    packet.getU32() // data signature
  }

  packet.getU32() // spr signature
  packet.getU32() // pic signature

  if (version >= 980) {
    packet.getU8() // preview state
  }

  let decryptedPacket = packet
  let xtea: number[] | null = null
  if (version >= 770) {
    decryptedPacket = packet.rsaDecrypt()

    if (decryptedPacket.getU8() !== 0) {
      throw `Rsa decryption error (1)`
    }

    xtea = [
      decryptedPacket.getU32(),
      decryptedPacket.getU32(),
      decryptedPacket.getU32(),
      decryptedPacket.getU32()
    ]
  }

  const accountName =
    version >= 840 ? decryptedPacket.getString() : decryptedPacket.getU32()

  const accountPassword = decryptedPacket.getString()

  console.log(CONSOLE_COLORS.WHITE, { accountName, accountPassword })

  // otclient extended data
  //decryptedPacket.getString()

  if (version >= 1061) {
    packet.getU8() // ogl info 1
    packet.getU8() // ogl info 2
    packet.getString() // gpu
    packet.getString() // gpu version
  }

  let accountToken: string = ''
  let stayLogged = true
  if (version >= 1072) {
    // auth token
    const decryptAuthPacket = packet.rsaDecrypt()
    if (decryptAuthPacket.getU8() !== 0) {
      throw 'RSA decryption error (2)'
    }

    accountToken = decryptAuthPacket.getString()
    if (version >= 1074) {
      stayLogged = decryptAuthPacket.getU8() > 0
    }
  }

  function disconnectClient(error: string, version: number, code?: number) {
    const output = new OutputMessage()
    if (code) {
      output.addU8(code)
    } else {
      output.addU8(version >= 1076 ? 0x0b : 0x0a)
    }

    output.addString(error)
    send(socket, output, hasCheksum, xtea)
  }

  if (version < VERSION_MIN || version > VERSION_MAX) {
    return disconnectClient(
      `Only clients with protocol between ${VERSION_MIN} and ${VERSION_MAX} allowed!`,
      version
    )
  }

  // onRecvFirstMessage end

  function getCharacterList(
    accountName: string | number,
    password: string,
    token: string,
    version: number
  ) {
    const output = new OutputMessage()
    const motd = 'Hello!'
    const characters = ['Account Manager']
    const serverIp = '127.0.0.1'
    const serverPort = 7172

    // token

    // motd
    if (motd && motd.length > 0) {
      output.addU8(0x14)
      output.addString(`1\n${motd}`)
    }

    // session key
    if (version >= 1074) {
      output.addU8(0x28)
      output.addString(
        `${accountName}\n${accountPassword}\n${accountToken}\n${Math.floor(
          Date.now() / 1000
        )}`
      )
    }

    output.addU8(0x64)

    if (version >= 1010) {
      // worlds
      const worlds = 2
      output.addU8(worlds)

      for (let i = 0; i < worlds; i++) {
        output.addU8(i)
        output.addString(i === 0 ? 'Offline' : 'Online')
        output.addString(serverIp)
        output.addU16(serverPort)
        output.addU8(0)
      }

      // characters
      output.addU8(characters.length)

      for (const character of characters) {
        output.addU8(0)
        output.addString(character)
      }
    } else {
      output.addU8(characters.length)

      for (const character of characters) {
        output.addString(character)

        output.addU32(ip2int(serverIp))
        output.addU16(serverPort)

        if (version >= 980) {
          output.addU8(0)
        }
      }
    }

    // premium
    if (version >= 1077) {
      output.addU8(0) // account status: 0 - OK, 1 - Frozen, 2 - Suspended
      output.addU8(0) // premium status: 0 - Free, 1 - Premium
      output.addU32(0)
    } else {
      output.addU16(0)
    }

    send(socket, output, hasCheksum, xtea)
  }

  getCharacterList(accountName, accountPassword, accountToken, version)
}

function send(
  socket: net.Socket,
  packet: OutputMessage,
  has_checksum: boolean,
  xtea?: number[] | null
) {
  if (xtea) {
    packet.xteaEncrypt(xtea)
  }

  if (has_checksum) {
    packet.addChecksum()
  }

  packet.addSize()

  if (socket) {
    // it's null when benchmarking
    socket.write(packet.getSendBuffer())
  }
}

function ip2int(ip: string): number {
  const d = ip.split('.')
  return (+d[3] << 24) + (+d[2] << 16) + (+d[1] << 8) + +d[0]
}
