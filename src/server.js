import http from 'http';
import dotenv from 'dotenv';
import { Server as SocketIOServer } from 'socket.io';
import app from './app.js';
import connectDB from './DB/connection.js';
import { Message } from './DB/models/message.model.js';

dotenv.config();

const PORT = process.env.PORT || 5000;

const startServer = async () => {
  await connectDB();

  const server = http.createServer(app);
  const io = new SocketIOServer(server, {
    cors: {
      origin: 'http://localhost:5173',
      methods: ['GET', 'POST'],
      credentials: true,
    },
  });

  io.on('connection', (socket) => {
    // eslint-disable-next-line no-console
    console.log('Socket connected', socket.id);

    socket.on('joinRoom', (roomId) => {
      socket.join(roomId);
    });

    socket.on('sendMessage', async (payload) => {
      const { roomId, senderId, content } = payload || {};
      if (!roomId || !senderId || !content) return;
      try {
        const messageDoc = await Message.create({
          negotiation: roomId,
          sender: senderId,
          text: content,
        });
        const message = {
          _id: messageDoc._id,
          negotiationId: roomId,
          senderId,
          content,
          createdAt: messageDoc.createdAt,
        };
        io.to(roomId).emit('receiveMessage', message);
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error('Error saving message', error);
      }
    });
  });

  server.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`EcoLink server listening on port ${PORT}  ✅`);
  });
};

startServer().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('Failed to start server:', err);
  process.exit(1);
});

