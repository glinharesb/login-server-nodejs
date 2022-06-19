import net from 'net'
import { onSocketData } from './onSocketData'
import { CONSOLE_COLORS } from './utils'

export class Server {
  host: string = '0.0.0.0'
  port: number = 7173
  exclusive: boolean = true

  init() {
    const server = net.createServer()

    server.on('connection', this.onConnection)
    server.on('listening', this.onListening.bind(this))

    server.listen({
      host: this.host,
      port: this.port,
      exclusive: this.exclusive
    })
  }

  onConnection(socket: net.Socket) {
    console.log(CONSOLE_COLORS.BLUE, `~> Client connected`)

    socket.on('data', (data) => onSocketData(socket, data))

    socket.on('close', (hadError) => {
      if (hadError) {
        return console.log(CONSOLE_COLORS.RED, `~> Client disconnected (error)`)
      }

      console.log(CONSOLE_COLORS.RED, `~> Client disconnected`)
    })

    socket.on('error', (err) => {
      console.log(CONSOLE_COLORS.RED, `~> Error`, err)
    })
  }

  onListening() {
    console.log(
      CONSOLE_COLORS.GREEN,
      `~> TCP Server is listening on: ${this.host}:${this.port}\n`
    )
  }
}
