import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

// Resolve .env path relative to this file so running node from within `src/` still picks up project root .env
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const resolvedEnvPath = path.resolve(__dirname, '../.env');
// load and show which .env file is used for debug
console.log('[socket-server] resolving .env ->', resolvedEnvPath);
dotenv.config({ path: resolvedEnvPath });

// Debug environment after imports
console.log('[socket-server] MONGO_URI present?', !!process.env.MONGO_URI);
console.log('[socket-server] JWT_SECRET present?', !!process.env.JWT_SECRET);
console.log('[socket-server] JWT_SECRET length:', process.env.JWT_SECRET?.length || 'undefined');

import http from 'http';
import { Server } from 'socket.io';
import {connectToDatabase} from './lib/db.js';
import ChatMessage from './models/ChatMessge.js';
import City from './models/City.js';
import User from './models/User.js';
import { verifyToken } from './lib/jwt.js';

const PORT = process.env.SOCKET_PORT || 4001;

async function start() {
  await connectToDatabase();
  const server = http.createServer();
  // Configure allowed origins via environment variable for production safety.
  const allowed = (process.env.SOCKET_ALLOWED_ORIGINS || 'http://localhost:3000').split(',').map(s => s.trim()).filter(Boolean);
  const io = new Server(server, {
    cors: {
      origin: allowed,
      methods: ['GET', 'POST'],
      credentials: true,
    },
    path: '/socket.io',
  });

  io.use(async (socket, next) => {
    try {
      // Log handshake origin for debugging in production
      console.log('socket handshake origin=', socket.handshake && socket.handshake.headers && socket.handshake.headers.origin);
      // Debug: log full cookie header and auth object
      console.log('socket auth object:', socket.handshake.auth);
      console.log('socket query:', socket.handshake.query);
      console.log('socket headers:', socket.handshake.headers);
      console.log('socket cookie header:', socket.handshake.headers.cookie);
      
      let token = null;
      
      // Method 1: Check auth object (multiple fields)
      if (socket.handshake.auth) {
        token = socket.handshake.auth.token || 
                socket.handshake.auth.authorization || 
                socket.handshake.auth.Authorization;
        
        // Handle Bearer format
        if (token && token.startsWith('Bearer ')) {
          token = token.substring(7);
        }
      }
      
      // Method 2: Check query parameters
      if (!token && socket.handshake.query) {
        token = socket.handshake.query.token || 
                socket.handshake.query.auth || 
                socket.handshake.query.authorization;
        
        // Handle Bearer format
        if (token && token.startsWith('Bearer ')) {
          token = token.substring(7);
        }
      }
      
      // Method 3: Check headers
      if (!token && socket.handshake.headers) {
        token = socket.handshake.headers.token || 
                socket.handshake.headers.authorization ||
                socket.handshake.headers.Authorization;
        
        // Handle Bearer format
        if (token && token.startsWith('Bearer ')) {
          token = token.substring(7);
        }
      }
      
      // Method 4: Parse cookies (existing logic)
      if (!token && socket.handshake && socket.handshake.headers && socket.handshake.headers.cookie) {
        // cookie string may look like: 'a=1; token=eyJ...; other=2'
        const m = /(?:^|; )token=([^;]+)/.exec(socket.handshake.headers.cookie);
        if (m) {
          token = m[1];
          console.log('extracted token from cookie:', token ? token.substring(0, 20) + '...' : 'null');
        } else {
          console.log('no token found in cookie header');
        }
      }
      
      console.log('🔍 Final extracted token:', token ? 'Present' : 'Missing');
      
      if (!token) {
        console.log('no token available, continuing as guest');
        return next();
      }
      
      const decoded = verifyToken(token);
      if (!decoded) {
        console.log('token verification failed');
        return next();
      }
      
      const user = await User.findById(decoded.userId).lean();
      if (user) {
        socket.user = { 
          userId: user._id.toString(), 
          username: user.username,
          email: user.email,
          decoded: decoded // Keep full JWT payload for debugging
        };
        console.log('✅ socket authenticated user:', user.username, 'userId:', user._id.toString());
      } else {
        console.log('❌ user not found in database for userId:', decoded.userId);
      }
      return next();
    } catch (err) {
      console.error('socket auth middleware error:', err);
      return next();
    }
  });

  io.on('connection', (socket) => {
    console.log('Socket connected', socket.id, 'user=', socket.user && socket.user.userId);
  // simple stats
  socket.serverStats = socket.serverStats || { connections: 0, messages: 0 };
  socket.serverStats.connections += 1;

    socket.on('joinRoom', ({ city, groupName }) => {
      const room = `${city}::${groupName}`;
      console.log('🚪 socket joinRoom:', { room, socketId: socket.id, userId: socket.user?.userId });
      socket.join(room);
    });

    socket.on('leaveRoom', ({ city, groupName }) => {
      const room = `${city}::${groupName}`;
      console.log('🚪 socket leaveRoom:', { room, socketId: socket.id });
      socket.leave(room);
    });

    socket.on('sendMessage', async (payload, ack) => {
      console.log('📩 socket sendMessage received:', { payload, socketId: socket.id, userId: socket.user?.userId });
      console.log('🔐 socket user object:', socket.user);
      
      try {
        const { city, groupName, text, media, _auth, token, authorization, userId, username } = payload || {};
        
        // Debug: log all potential auth fields in payload
        console.log('🔍 Auth fields in payload:', { _auth: !!_auth, token: !!token, authorization: !!authorization, userId, username });
        
        if (!city || !groupName) {
          console.warn('❌ sendMessage missing fields:', { city, groupName });
          if (typeof ack === 'function') ack({ success: false, message: 'Missing fields' });
          return;
        }
        
        const cityDoc = await City.findOne({ cityName: city });
        if (!cityDoc) {
          console.warn('❌ sendMessage city not found:', city);
          if (typeof ack === 'function') ack({ success: false, message: 'City not found' });
          return;
        }

        // Try to get authenticated user ID from multiple sources
        let authenticatedUserId = null;
        
        // Method 1: From socket.user (preferred)
        if (socket.user && socket.user.userId) {
          authenticatedUserId = socket.user.userId;
          console.log('✅ Using socket.user.userId:', authenticatedUserId);
        }
        // Method 2: Try to authenticate using token from payload
        else if (_auth || token || authorization) {
          const payloadToken = _auth || token || (authorization && authorization.startsWith('Bearer ') ? authorization.substring(7) : authorization);
          console.log('🔄 Attempting auth with payload token...');
          
          if (payloadToken) {
            const decoded = verifyToken(payloadToken);
            if (decoded) {
              const user = await User.findById(decoded.userId).lean();
              if (user) {
                authenticatedUserId = user._id.toString();
                console.log('✅ Authenticated via payload token:', user.username);
                // Update socket.user for future requests
                socket.user = { 
                  userId: user._id.toString(), 
                  username: user.username,
                  email: user.email 
                };
              }
            }
          }
        }

        if (!authenticatedUserId) {
          console.warn('❌ sendMessage user not authenticated');
          console.warn('❌ Debug info:', { 
            hasSocketUser: !!socket.user, 
            socketUserId: socket.user?.userId,
            hasPayloadAuth: !!(_auth || token || authorization),
            payloadUserId: userId 
          });
          if (typeof ack === 'function') ack({ success: false, message: 'Unauthenticated' });
          return;
        }

        console.log('✅ sendMessage authenticated userId:', authenticatedUserId);
        console.log('💾 saving message to database...');
        const msg = new ChatMessage({ 
          city: cityDoc._id, 
          groupName, 
          sender: authenticatedUserId, 
          text, 
          media: media || [] 
        });
        await msg.save();
        console.log('✅ message saved, populating...');
        const populated = await ChatMessage.findById(msg._id).populate('sender', 'username profileImage');
        console.log('✅ message populated, broadcasting to room...');
  const out = populated.toObject ? populated.toObject() : populated;
  out.senderId = out.sender && (out.sender._id || out.sender.id) ? String(out.sender._id || out.sender.id) : (out.sender || null);
  // Add city name and group name to the broadcast message so client can identify the correct room
  out.cityName = city; // use the original city name from the request
  out.groupName = groupName; // ensure groupName is included
  const room = `${city}::${groupName}`;
        console.log('📡 broadcasting to room:', room);
        const roomSockets = io.sockets.adapter.rooms.get(room);
        console.log('👥 sockets in room:', roomSockets ? roomSockets.size : 0);
        console.log('📤 broadcasting message data:', { id: out._id, text: out.text, sender: out.sender?.username, cityName: out.cityName });
  io.to(room).emit('message', out);
  // increment message count
  socket.serverStats.messages += 1;
        console.log('✅ sending success ack to client');
        if (typeof ack === 'function') ack({ success: true, data: out });
      } catch (err) {
        console.error('socket sendMessage error', err);
        if (typeof ack === 'function') ack({ success: false, message: err.message });
      }
    });

    socket.on('deleteMessage', async (payload, ack) => {
      try {
        const { messageId } = payload || {};
        if (!messageId) {
          if (typeof ack === 'function') ack({ success: false, message: 'Missing messageId' });
          return;
        }
        const msg = await ChatMessage.findById(messageId).lean();
        if (!msg) {
          if (typeof ack === 'function') ack({ success: false, message: 'Message not found' });
          return;
        }
        const userId = socket.user ? socket.user.userId : null;
        // compute sender id robustly: msg.sender may be ObjectId or populated
        const senderId = msg.sender && msg.sender._id ? String(msg.sender._id) : String(msg.sender);
        console.log('socket deleteMessage attempt', { messageId, requester: userId, senderId });
        if (!userId || String(senderId) !== String(userId)) {
          console.warn('socket deleteMessage forbidden', { messageId, requester: userId, senderId });
          if (typeof ack === 'function') ack({ success: false, message: 'Forbidden' });
          return;
        }
        const deleted = await ChatMessage.findByIdAndDelete(messageId);
        console.log('socket deleteMessage deleted', { messageId, deleted: !!deleted });
        // broadcast deletion to room
        // need cityName
        const cityDoc = await City.findById(msg.city).lean();
        const room = `${cityDoc?.cityName || 'unknown'}::${msg.groupName}`;
        const out = { id: messageId, cityName: cityDoc?.cityName, groupName: msg.groupName };
        io.to(room).emit('deleteMessage', out);
        if (typeof ack === 'function') ack({ success: true, data: out });
      } catch (err) {
        console.error('socket deleteMessage error', err);
        if (typeof ack === 'function') ack({ success: false, message: err.message });
      }
    });

    // lightweight announce used by clients after they successfully delete via HTTP
    socket.on('announceDelete', (payload) => {
      try {
        const { id, cityName, groupName } = payload || {};
        if (!id) return;
        const room = `${cityName || 'unknown'}::${groupName || 'Open Chat'}`;
        const out = { id, cityName, groupName };
        io.to(room).emit('deleteMessage', out);
      } catch (err) {
        console.error('announceDelete handling error', err);
      }
    });

    socket.on('disconnect', () => {
      // cleanup if required
    });
  });

  server.listen(PORT, () => console.log(`Socket server listening on port ${PORT}`));
  // process-level monitoring/logging hooks
  process.on('uncaughtException', (err) => { console.error('uncaughtException', err); process.exit(1); });
  process.on('unhandledRejection', (reason) => { console.error('unhandledRejection', reason); process.exit(1); });
}

start().catch(err => { console.error('Failed to start socket server', err); process.exit(1); });
