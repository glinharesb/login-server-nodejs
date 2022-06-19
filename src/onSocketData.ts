import net from 'net'
import { InputMessage } from './InputMessage'
import { onSocketPacket } from './onSocketPacket'

interface ISocketData {
  size: number
  pos: number
  packet: null | Buffer
}

export async function onSocketData(socket: net.Socket, data: Buffer) {
  const socketData: ISocketData = {
    size: 0,
    pos: 0,
    packet: null
  }

  let dataPos = 0
  while (dataPos < data.length) {
    // read header
    if (socketData.packet === null) {
      if (data.length < 2) {
        socket.destroy()
        return
      }

      socketData.size = data.readInt16LE(0)
      if (socketData.size > 1024) {
        socket.destroy()
        return
      }

      socketData.packet = Buffer.allocUnsafe(socketData.size)
      socketData.pos = 0

      dataPos += 2
    }

    const copiedBytes = data.copy(
      socketData.packet,
      socketData.pos,
      dataPos,
      Math.min(data.length, dataPos + socketData.size - socketData.pos)
    )

    dataPos += copiedBytes
    socketData.pos += copiedBytes

    if (socketData.pos === socketData.size) {
      try {
        await onSocketPacket(socket, new InputMessage(socketData.packet))

        socket.end()
        break // end connection after first packet
      } catch (error) {
        // invalid packet
        console.log(error)
        socket.destroy()
        break
      }
    }
  }
}
