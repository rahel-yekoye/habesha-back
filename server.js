require('dotenv').config({ path: './secret.env' });
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Message = require('./models/message'); 
const User = require('./models/user'); 
const Group = require('./models/group'); 
const { parsePhoneNumberFromString } = require('libphonenumber-js');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const Joi = require('joi'); 
const { groupSchema } = require('./schemas'); 
const app = express();
const fs = require('fs'); 
const port = 4000;

const verificationCodes = new Map();
const callTimers = {};

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: '*', 
    methods: ['GET', 'POST']
  }
});
//middleware ..cors handles frontend requests and express the api framework
app.use(cors());
app.use(express.json());

// Normalize a 1:1 room ID deterministically
function normalizeRoomId(user1, user2) {
  return user1 < user2 ? `${user1}_${user2}` : `${user2}_${user1}`;
}

// In-memory presence map: { [userId]: { online: boolean, lastSeen: number, socketId: string } }
const presence = {};

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log(' Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

app.get('/', (req, res) => {
  res.send(' Chat App Backend with Real-Time is Running!');
});

// Presence lookup for a set of users
app.get('/presence', authenticateToken, (req, res) => {
  const users = (req.query.users || '')
    .toString()
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  const result = {};
  users.forEach((u) => {
    const p = presence[u];
    result[u] = p ? { online: !!p.online, lastSeen: p.lastSeen || null } : { online: false, lastSeen: null };
  });
  res.json(result);
});

const registerSchema = Joi.object({
  username: Joi.string().required(),
  email: Joi.string().email().required(),
  phoneNumber: Joi.string().required(),
  password: Joi.string().min(6).required(),
});


app.post('/register', async (req, res) => {
  const { error } = registerSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  const { username, email, phoneNumber, password } = req.body;

  console.log('Received registration data:', req.body);

  if (!username || !email || !phoneNumber || !password) {
    console.log('Missing required fields'); 
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      console.log('Username already exists:', username); 
      return res.status(400).json({ error: 'Username already exists' });
    }

    const existingPhone = await User.findOne({ phoneNumber });
    if (existingPhone) {
      console.log('Phone number already exists:', phoneNumber); 
      return res.status(400).json({ error: 'Phone number already exists' });
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    console.log('Generated verification code:', verificationCode); 

    verificationCodes.set(email, { username, phoneNumber, password, verificationCode });

    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: 'tnegussie14@gmail.com',
      to: email,
      subject: 'Email Verification Code',
      text: `Your verification code is: ${verificationCode}`,
    });

    res.status(201).json({ message: 'Verification code sent to your email' });
  } catch (error) {
    console.error('Error during registration:', error); 
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/verify', async (req, res) => {
  const { email, verificationCode } = req.body;

  if (!email || !verificationCode) {
    return res.status(400).json({ error: 'Email and verification code are required' });
  }

  try {
    const userData = verificationCodes.get(email);
    if (!userData || userData.verificationCode !== verificationCode) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const parsedPhoneNumber = parsePhoneNumberFromString(userData.phoneNumber, 'ET');
    const normalizedPhoneNumber = parsedPhoneNumber ? parsedPhoneNumber.number : userData.phoneNumber;

    const newUser = new User({
      username: userData.username,
      email,
      phoneNumber: normalizedPhoneNumber, // <-- always save normalized!
      password: hashedPassword,
    });
    await newUser.save();
    verificationCodes.delete(email);

    const token = jwt.sign({ id: newUser._id, email: newUser.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(201).json({
      token,
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
      },
    });

  } catch (error) {
    console.error('Error during verification:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  console.log('Login request body:', req.body); // Debugging log

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  console.log('Authorization Header:', req.headers['authorization']);
  const token = authHeader && authHeader.split(' ')[1]; 

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Token verification failed:', err.message);
      return res.status(403).json({ error: 'Invalid or malformed token.' });
    }
    req.user = user; // Attach the user payload to the request
    next();
  });
}

// Do not log secrets in production

// Rate limiter
const searchLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests, please try again later.',
});

// Secured /search endpoint
app.get('/search', authenticateToken, async (req, res) => {
  console.log('Authenticated user:', req.user); 
  const { phoneNumber } = req.query;

  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  try {
    console.log('Received phone number:', phoneNumber); // Debug log

    const { parsePhoneNumberFromString } = require('libphonenumber-js');
    const parsedPhoneNumber = parsePhoneNumberFromString(phoneNumber, 'ET'); // Replace 'ET' with your default country code
    if (!parsedPhoneNumber || !parsedPhoneNumber.isValid()) {
      console.log('Invalid phone number format:', phoneNumber); // Debug log
      return res.status(400).json({ error: 'Invalid phone number format' });
    }
    const normalizedPhoneNumber = parsedPhoneNumber.number;
    console.log('Normalized phone number:', normalizedPhoneNumber); // Debug log

    const user = await User.findOne({ phoneNumber: normalizedPhoneNumber });
    if (!user) {
      console.log('User not found for phone number:', normalizedPhoneNumber); // Debug log
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('User found:', user); // Debug log
    res.json({ success: true, user: { username: user.username, phoneNumber: user.phoneNumber } });
  } catch (error) {
    console.error('Error searching for user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Unified deletion endpoint supporting both modes: 'for_me' (soft delete) and 'for_everyone' (global delete)
// Request body: { ids: string[], mode: 'for_me' | 'for_everyone', otherUser?: string }
app.delete('/messages', authenticateToken, async (req, res) => {
  try {
    const { ids, mode, otherUser } = req.body || {};

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Message IDs must be a non-empty array' });
    }
    if (mode !== 'for_me' && mode !== 'for_everyone') {
      return res.status(400).json({ error: "mode must be either 'for_me' or 'for_everyone'" });
    }

    if (mode === 'for_me') {
      // Soft delete for current user only: pull user from visibleTo
      const result = await Message.updateMany(
        { _id: { $in: ids }, visibleTo: req.user.id },
        { $pull: { visibleTo: req.user.id } }
      );

      // Notify only this user's other clients to remove messages immediately
      io.to(req.user.id).emit('messages_deleted_for_me', { messageIds: ids });

      return res.json({ success: true, updatedCount: result.modifiedCount ?? result.nModified ?? 0 });
    }

    // Delete for everyone: mark messages as deleted and sanitize content
    const docs = await Message.find({ _id: { $in: ids } });
    if (!docs.length) {
      return res.status(404).json({ error: 'No messages found for provided IDs' });
    }

    await Message.updateMany(
      { _id: { $in: ids } },
      {
        $set: {
          deleted: true,
          content: 'This message was deleted',
          fileUrl: '',
          emojis: [],
        },
      }
    );

    // Determine target rooms to notify (by roomId or by normalized 1:1 room)
    const rooms = new Set();
    for (const m of docs) {
      if (m.roomId) {
        rooms.add(m.roomId);
      } else if (m.sender && m.receiver) {
        rooms.add((m.sender < m.receiver) ? `${m.sender}_${m.receiver}` : `${m.receiver}_${m.sender}`);
      }
    }
    for (const r of rooms) {
      io.to(r).emit('messages_deleted_for_everyone', { messageIds: ids });
    }

    return res.json({ success: true, updatedCount: ids.length });
  } catch (error) {
    console.error('Error in unified message deletion:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Real-time Socket.IO connection
const userIdToSocketId = {};

io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  socket.on('register_user', (userId) => {
    userIdToSocketId[userId] = socket.id;
    socket.data.userId = userId;
    socket.join(userId);
    console.log(`[SOCKET] User ${userId} registered (socket.id: ${socket.id})`);
    console.log(`[SOCKET] Current registered users:`, Object.keys(userIdToSocketId));
    
    // Send test event to verify socket is working
    socket.emit('test_event', { message: 'Socket connection verified', userId: userId });
  });

  socket.on('disconnect', () => {
    for (const [userId, sId] of Object.entries(userIdToSocketId)) {
      if (sId === socket.id) {
        delete userIdToSocketId[userId];
        break;
      }
    }
  });

  // Register user to their own room for signaling
// Handle group message sending
socket.on('send_group_message', async (data) => {
  const { groupId, sender, content, clientId, fileUrl } = data;
  console.log('📥 Received send_group_message:', data);

  if (!groupId || !sender || (!content && !fileUrl)) {
    console.error('❌ Missing fields in send_group_message:', data);
    return;
  }

  try {
    const message = new Message({
      sender,
      groupId,
      content,
      isGroup: true,
      timestamp: new Date(),
      clientId: clientId || null,    // ✅ Save clientId
      fileUrl: fileUrl || '',        // ✅ Save fileUrl
    });

    await message.save();
    console.log('✅ Message saved to database:', message);

    io.to(groupId).emit('group_message', {
      _id: message._id.toString(),        // ✅ Optional but ideal for syncing
      clientId: message.clientId,
      groupId,
      sender,
      content: message.content,
      timestamp: message.timestamp,
      fileUrl: message.fileUrl,
    });

    console.log(`📤 Message emitted to group ${groupId}:`, {
      sender,
      content: message.content,
      timestamp: message.timestamp,
      clientId: message.clientId,
      fileUrl: message.fileUrl,
    });
  } catch (error) {
    console.error('❌ Error saving or emitting message:', error);
  }
});

// Handle joining groups
socket.on('join_group', (groupIds) => {
  console.log('📥 Received join_group payload:', groupIds);

  // Defensive check: accept string or array of strings
  if (typeof groupIds === 'string') {
    groupIds = [groupIds];
  }

  if (!Array.isArray(groupIds)) {
    console.warn('⚠️ join_group payload is neither string nor array:', groupIds);
    return;
  }

  groupIds.forEach((groupId, index) => {
    if (typeof groupId === 'string' && groupId.trim().length > 0) {
      socket.join(groupId);
      console.log(`Socket ${socket.id} joined room ${groupId}`);
console.log('Current clients in room:', io.sockets.adapter.rooms.get(groupId));

      socket.emit('joined_group', groupId); // Used by frontend to confirm
      console.log(`✅ User ${socket.id} joined group [${index}]: ${groupId}`);
    } else {
      console.warn(`⚠️ Empty or invalid groupId at index ${index}:`, groupId);
    }
  });
});

  socket.on('join_room', (roomId) => {
    socket.join(roomId);
    console.log(`User ${socket.id} joined room: ${roomId}`);
    // Print all sockets in the room
    const room = io.sockets.adapter.rooms.get(roomId);
    console.log(`Current sockets in room ${roomId}:`, room ? Array.from(room) : []);
  });

  // Typing indicators
  socket.on('typing', (data) => {
    // data: { roomId, from, to, isGroup }
    if (data?.isGroup && data?.roomId) {
      io.to(data.roomId).emit('typing', { from: data.from, roomId: data.roomId, isGroup: true });
    } else if (data?.to) {
      io.to(data.to).emit('typing', { from: data.from, to: data.to, isGroup: false });
    }
  });

  socket.on('stop_typing', (data) => {
    if (data?.isGroup && data?.roomId) {
      io.to(data.roomId).emit('stop_typing', { from: data.from, roomId: data.roomId, isGroup: true });
    } else if (data?.to) {
      io.to(data.to).emit('stop_typing', { from: data.from, to: data.to, isGroup: false });
    }
  });

  // Reactions: add or update a user's reaction on a message
  socket.on('add_reaction', async (data) => {
    try {
      const { messageId, user, emoji } = data || {};
      console.log(`📡 Received add_reaction:`, { messageId, user, emoji });
      if (!messageId || !user || !emoji) return;

      const msg = await Message.findById(messageId);
      if (!msg) {
        console.log(`❌ Message not found: ${messageId}`);
        return;
      }

      // Ensure only one reaction per user: remove previous then add new
      await Message.updateOne(
        { _id: messageId },
        { $pull: { reactions: { user } } }
      );
      await Message.updateOne(
        { _id: messageId },
        { $push: { reactions: { user, emoji } } }
      );

      const updated = await Message.findById(messageId).lean();
      const room = updated.roomId || normalizeRoomId(updated.sender, updated.receiver);
      console.log(`📡 Emitting reactions update to room ${room}:`, {
        messageId,
        reactions: updated.reactions || [],
      });
      io.to(room).emit('message_reactions_updated', {
        messageId,
        reactions: updated.reactions || [],
      });
    } catch (e) {
      console.error('Error in add_reaction:', e);
    }
  });

  // Reactions: remove a user's reaction
  socket.on('remove_reaction', async (data) => {
    try {
      const { messageId, user } = data || {};
      console.log(`📡 Received remove_reaction:`, { messageId, user });
      if (!messageId || !user) return;

      const msg = await Message.findById(messageId);
      if (!msg) {
        console.log(`❌ Message not found: ${messageId}`);
        return;
      }

      await Message.updateOne(
        { _id: messageId },
        { $pull: { reactions: { user } } }
      );

      const updated = await Message.findById(messageId).lean();
      const room = updated.roomId || normalizeRoomId(updated.sender, updated.receiver);
      console.log(`📡 Emitting reactions removal to room ${room}:`, {
        messageId,
        reactions: updated.reactions || [],
      });
      io.to(room).emit('message_reactions_updated', {
        messageId,
        reactions: updated.reactions || [],
      });
    } catch (e) {
      console.error('Error in remove_reaction:', e);
    }
  });

// Handle sending messages
socket.on('send_message', async (data) => {
  console.log('📨 Received send_message event:', data);

  // Destructure with clientId included
  const {
    roomId,
    sender,
    receiver,
    content,
    timestamp,
    fileUrl,
    clientId,
    replyTo,
  } = data;

  const normalizedRoomId = normalizeRoomId(sender, receiver);

  // Validate required fields
  if (!roomId || !sender || !receiver || !timestamp) {
    console.error('❌ Missing required fields for send_message:', {
      roomId: !!roomId,
      sender: !!sender,
      receiver: !!receiver,
      content: !!content,
      timestamp: !!timestamp,
    });
    return;
  }

  try {
    // Construct message
    const message = new Message({
      sender,
      receiver,
      content,
      roomId: normalizedRoomId,
      isGroup: false,
      timestamp: new Date(timestamp),
      fileUrl: fileUrl || '',
      visibleTo: [sender, receiver],
      readBy: [sender],
      direction: 'outgoing',
      clientId: clientId || null, // ✅ Save clientId if needed for tracking
      replyTo: replyTo || null,
    });

    await message.save();
    console.log(' Message saved to database:', message);

    // Emit to room: client can filter by clientId to avoid duplication
    io.to(normalizedRoomId).emit('receive_message', {
      _id: message._id.toString(),        // Ensure string
      id: message._id.toString(),         // Convenience for frontend models
      roomId: normalizedRoomId,
      sender: message.sender,
      receiver: message.receiver,
      content: message.content,
      fileUrl: message.fileUrl || '',
      isGroup: false,
      visibleTo: message.visibleTo,
      isFile: !!message.fileUrl,
      deleted: message.deleted,
      edited: message.edited,
      direction: 'incoming',
      duration: message.duration ?? null,
      timestamp: message.timestamp.toISOString(),
      readBy: message.readBy,
      visibleTo: message.visibleTo,
      emojis: message.emojis,
      clientId: message.clientId, // Echo back to allow deduplication
      replyTo: message.replyTo,
      reactions: message.reactions || [],
    });

    console.log(` Message emitted to room ${normalizedRoomId}`);

    // Delivery ack: if receiver is online (has a socket), notify the sender
    const receiverSocketId = userIdToSocketId[receiver];
    if (receiverSocketId) {
      io.to(sender).emit('message_delivered', {
        messageId: message._id.toString(),
        clientId: clientId || null,
        to: receiver,
      });
      console.log(` Delivered ack sent to ${sender} for message ${message._id}`);
    }

    // Mark as read immediately if receiver is in the room
    const room = io.sockets.adapter.rooms.get(normalizedRoomId);

    if (room && receiverSocketId && room.has(receiverSocketId)) {
      await Message.updateOne(
        { _id: message._id },
        { $addToSet: { readBy: receiver } }
      );

      io.to(normalizedRoomId).emit('message_read', {
        messageId: message._id.toString(),
        reader: receiver,
      });

      console.log(`✅ Message marked as read by ${receiver}`);
    }

    // Emit conversation updates (inbox-style)
    const updateForReceiver = {
      otherUser: sender,
      message: message.content,
      timestamp: message.timestamp.toISOString(),
      isGroup: false,
    };

    const updateForSender = {
      otherUser: receiver,
      message: message.content,
      timestamp: message.timestamp.toISOString(),
      isGroup: false,
    };

    io.to(receiver).emit('conversation_update', updateForReceiver);
    io.to(sender).emit('conversation_update', updateForSender);

  } catch (error) {
    console.error('❌ Error saving or emitting message:', error);
  }
});

socket.on('mark_as_read', async ({ user, otherUser }) => {
  const roomId = [user, otherUser].sort().join('_');
  const messages = await Message.find({
    roomId,
    readBy: { $ne: user }, // unread by this user
    receiver: user,        // only mark ones received
  });

const messageIds = messages.map(msg => msg._id.toString());

  await Message.updateMany(
    { _id: { $in: messageIds } },
    { $addToSet: { readBy: user } }
  );

  io.to(roomId).emit('messages_read', {
    messageIds,
    reader: user,
  });
});



// PUT /messages/mark-read (must come before /messages/:id)
// Request body: { user: 'username', otherUser: 'username' }

app.put('/messages/mark-read', authenticateToken, async (req, res) => {
  const { user, otherUser } = req.body;

  if (!user || !otherUser) return res.status(400).json({ error: 'Missing parameters' });

  const roomId = normalizeRoomId(user, otherUser);

  try {
    const messagesToUpdate = await Message.find({
      roomId,
      visibleTo: { $in: [user] },
      readBy: { $ne: user },
    });

    const messageIds = messagesToUpdate.map(msg => msg._id);
    await Message.updateMany(
      { _id: { $in: messageIds } },
      { $addToSet: { readBy: user } }
    );

    const readMessageIds = messageIds.map(id => id.toString());

    // Notify the receiver (otherUser) if online
    const senderSocketId = userIdToSocketId[otherUser];
    if (senderSocketId) {
      io.to(senderSocketId).emit('messages_read', {
        reader: user,
        messageIds: readMessageIds,
      });
    }

    res.json({ success: true, updatedCount: readMessageIds.length });

  } catch (err) {
    console.error('Error marking messages as read:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


  // --- OLD CALL SYSTEM REMOVED ---

  // New call system events
  
  socket.on('call_initiate', (data) => {
    console.log(`[CALL] Call initiated by ${data.from} to ${data.to}`);
    console.log(`[CALL] Data received:`, JSON.stringify(data, null, 2));
    console.log(`[CALL] Current registered users:`, Object.keys(userIdToSocketId));
    console.log(`[CALL] Full userIdToSocketId mapping:`, userIdToSocketId);
    const targetSocketId = userIdToSocketId[data.to];
    console.log(`[CALL] Target socket ID for ${data.to}: ${targetSocketId}`);
    
    if (targetSocketId) {
      console.log(`[CALL] Emitting incoming_call to socket ${targetSocketId}`);
      io.to(targetSocketId).emit('incoming_call', {
        from: data.from,
        callId: data.callId,
        isVideo: data.isVideo,
        callerName: data.callerName,
      });
    } else {
      console.log(`[CALL] No socket found for user ${data.to} - user may be offline`);
      console.log(`[CALL] Available users: ${Object.keys(userIdToSocketId).join(', ')}`);
    }
  });

  socket.on('call_offer', (data) => {
    console.log(`Call offer from ${data.from} to ${data.to}`);
    const targetSocketId = userIdToSocketId[data.to];
    if (targetSocketId) {
      io.to(targetSocketId).emit('call_offer', {
        from: data.from,
        offer: data.offer,
        callId: data.callId,
        isVideo: data.isVideo,
      });
    }
  });

  socket.on('call_answer', (data) => {
    console.log(`Call answer from ${data.from} to ${data.to}`);
    const targetSocketId = userIdToSocketId[data.to];
    if (targetSocketId) {
      io.to(targetSocketId).emit('call_answer', {
        from: data.from,
        answer: data.answer,
        callId: data.callId,
      });
    }
  });

  socket.on('call_answered', (data) => {
    console.log(`Call answered by ${data.from} for ${data.to}`);
    const targetSocketId = userIdToSocketId[data.to];
    if (targetSocketId) {
      io.to(targetSocketId).emit('call_answered', {
        from: data.from,
        callId: data.callId,
      });
    }
  });

  socket.on('call_decline', (data) => {
    console.log(`Call declined by ${data.from} to ${data.to}`);
    const targetSocketId = userIdToSocketId[data.to];
    if (targetSocketId) {
      io.to(targetSocketId).emit('call_decline', {
        from: data.from,
        callId: data.callId,
      });
    }
  });

  socket.on('call_end', (data) => {
    console.log(`Call ended by ${data.from} for ${data.to}`);
    const targetSocketId = userIdToSocketId[data.to];
    if (targetSocketId) {
      io.to(targetSocketId).emit('call_end', {
        from: data.from,
        callId: data.callId,
      });
    }
  });

  // ICE candidates exchange
  socket.on('ice_candidate', (data) => {
    const targetSocketId = userIdToSocketId[data.to];
    if (targetSocketId) {
      io.to(targetSocketId).emit('ice_candidate', {
        candidate: data.candidate,
        from: data.from,
      });
    }
  });

  

  socket.on('make_answer', (data) => {
    const targetSocketId = userIdToSocketId[data.to];
    if (targetSocketId) {
      io.to(targetSocketId).emit('answer_made', {
        answer: data.answer,
        from: data.from,
      });
      console.log(`[DEBUG] Sent answer_made to socket ${targetSocketId}`);
    } else {
      console.log(`[ERROR] No socket found for user ${data.to}`);
    }
  });

  // Handle call_answered event to stop caller from continuing to call
  socket.on('call_answered', (data) => {
    console.log(`[SOCKET] call_answered: from=${data.from}, to=${data.to}`);
    const callKey = `${data.to}_${data.from}`; // Note: reversed for caller's timer
    if (callTimers[callKey]) {
      clearTimeout(callTimers[callKey]);
      delete callTimers[callKey];
      console.log(`[SOCKET] Cleared call timer for ${callKey}`);
    }
    
    // Notify the caller that call was answered
    io.to(data.to).emit('call_answered', {
      from: data.from,
      to: data.to,
    });
  });

  // When a call ends after being answered
  function emitCallLog(callerId, calleeId, durationSeconds) {
    console.log('Emitting call log:', callerId, calleeId, durationSeconds);
    // For caller (outgoing)
    const outgoingLog = {
      sender: callerId,
      receiver: calleeId,
      type: 'call_log',
      direction: 'outgoing',
      duration: durationSeconds,
      timestamp: new Date().toISOString(),
      content: 'Outgoing call',
      visibleTo: [callerId]
    };
    // For callee (incoming)
    const incomingLog = {
      sender: calleeId,
      receiver: callerId,
      type: 'call_log',
      direction: 'incoming',
      duration: durationSeconds,
      timestamp: new Date().toISOString(),
      content: 'Incoming call',
      visibleTo: [calleeId]
    };
    io.to(callerId).emit('call_log', outgoingLog);
    io.to(calleeId).emit('call_log', incomingLog);
    Message.create(outgoingLog);
    Message.create(incomingLog);
  }

  socket.on('join', (userId) => {
    socket.join(userId);
    // Mark user online
    presence[userId] = { online: true, lastSeen: Date.now(), socketId: socket.id };
    io.emit('presence_update', { userId, online: true, lastSeen: presence[userId].lastSeen });
  });

  socket.on('heartbeat', (userId) => {
    if (presence[userId]) {
      presence[userId].lastSeen = Date.now();
    }
  });

  socket.on('disconnect', () => {
    // Find the user by socketId and mark offline
    const entry = Object.entries(presence).find(([, v]) => v.socketId === socket.id);
    if (entry) {
      const [uid] = entry;
      presence[uid] = { online: false, lastSeen: Date.now(), socketId: null };
      io.emit('presence_update', { userId: uid, online: false, lastSeen: presence[uid].lastSeen });
    }
  });
});



// API route to send message (for compatibility if needed)
app.post('/messages', authenticateToken, async (req, res) => {
  try {
    console.log('New message received via API:', req.body);
    const { sender, receiver, content } = req.body;

    // Check if the message already exists in the database
    const existingMessage = await Message.findOne({ sender, receiver, content });

    if (!existingMessage) {
      console.log('No duplicate message found, saving message.');
    } else {
      console.log('Duplicate message detected:', existingMessage);
    }

    if (!existingMessage) {
      const message = new Message({ sender, receiver, content });
      await message.save();

      // Emit real-time message to sender and receiver rooms
      io.to(sender).emit('receive_message', message);
      io.to(receiver).emit('receive_message', message);

      res.json({ success: true, message: 'Message sent!', data: message });
    } else {
      console.log('Duplicate message detected, not saving.');
      res.json({ success: false, message: 'Duplicate message detected' });
    }
  } catch (error) {
    console.error('❌ Error sending message:', error);
    res.status(500).json({ success: false, message: 'Failed to send message', error });
  }
});

// API route to get chat history
app.get('/messages', authenticateToken, async (req, res) => {
  const { user1, user2, currentUser } = req.query;
  const limit = Math.min(parseInt(req.query.limit) || 30, 100);
  const before = req.query.before ? new Date(req.query.before) : null;

  console.log(`[API] GET /messages called with user1=${user1}, user2=${user2}, currentUser=${currentUser}`);

  if (!user1 || !user2 || !currentUser) {
    console.warn('[API] Missing required query parameters');
    return res.status(400).json({ error: 'user1, user2, and currentUser are required' });
  }

  try {
    const match = {
      $and: [
        { $or: [ { sender: user1, receiver: user2 }, { sender: user2, receiver: user1 } ] },
        { visibleTo: currentUser }
      ]
    };

    if (before && !isNaN(before.getTime())) {
      match.$and.push({ timestamp: { $lt: before } });
    }

    const messagesDesc = await Message.find(match)
      .sort({ timestamp: -1 })
      .limit(limit)
      .lean();

    const messages = messagesDesc.reverse();

    if (!messages.length) {
      console.log('[API] No messages found for the conversation');
    } else {
      console.log(`[API] Fetched ${messages.length} messages`);
    }

    res.json(messages);
  } catch (error) {
    console.error('[API] Error fetching messages:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Configure storage for uploaded files (images, audio, etc.)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads/');
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ storage });

// Serve uploaded files statically
app.use('/uploads', express.static('uploads'));

// File upload endpoint
app.post('/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
const ip = req.headers.host; // e.g., "localhost:4000"
const fileUrl = `http://${ip}/uploads/${req.file.filename}`;
res.json({ fileUrl });
});

// API route to get all conversations for a user
app.get('/conversations', authenticateToken, async (req, res) => {
  const { user } = req.query;

  if (!user) {
    return res.status(400).json({ error: 'User is required' });
  }

  try {
    const conversations = await Message.aggregate([
      {
        $match: {
          $and: [
            {
              $or: [
                { sender: user },
                { receiver: user },
              ],
            },
            { isGroup: { $ne: true } }
          ]
        },
      },
      { $sort: { timestamp: -1 } },
      {
        $group: {
          _id: {
            $cond: [
              { $eq: ['$sender', user] },
              '$receiver',
              '$sender',
            ],
          },
          latestMessage: { $first: '$$ROOT' },
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id", // or "username" if you use usernames
          as: "userInfo"
        }
      },
      {
        $addFields: {
          otherUser: { $arrayElemAt: ["$userInfo.username", 0] }
        }
      }
    ]);

    // Calculate unread counts for each conversation
    const conversationsWithUnread = await Promise.all(
      conversations.map(async (conv) => {
        const otherUser = conv.otherUser || conv._id;
        const roomId = normalizeRoomId(user, otherUser);
        
        // Count unread messages (messages not read by current user)
        const unreadQuery = {
          $or: [
            { roomId },
            { sender: otherUser, receiver: user },
            { sender: user, receiver: otherUser }
          ],
          sender: { $ne: user }, // Only count messages NOT sent by current user
          readBy: { $not: { $in: [user] } }, // Not read by current user
          visibleTo: { $in: [user] }, // Visible to current user
        };
        
        const unreadCount = await Message.countDocuments(unreadQuery);
        
        console.log(`📊 Unread count for ${user} <-> ${otherUser}:`, {
          roomId,
          unreadCount,
          query: unreadQuery
        });

        return {
          otherUser: otherUser,
          message: conv.latestMessage.content || '[No Content]',
          timestamp: conv.latestMessage.timestamp || new Date().toISOString(),
          unreadCount: unreadCount,
        };
      })
    );

    res.json(conversationsWithUnread);
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/groups', authenticateToken, async (req, res) => {
  const { name, description, members } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Group name is required' });
  }

  try {
    const group = new Group({
      name,
      description,
      members: [req.user.id, ...members], // Add creator as a member
      createdBy: req.user.id, // Optionally track who created the group
    });

    await group.save();
    res.status(201).json(group);
  } catch (error) {
    console.error('Error creating group:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/groups/:groupId/add', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  const { members } = req.body;

  try {
    const group = await Group.findById(groupId);

    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }

    group.members.push(...members);
    await group.save();

    // Notify the added members (real-time notification)
    members.forEach((memberId) => {
      io.to(memberId).emit('group_notification', {
        message: `You have been added to the group: ${group.name}`,
        groupId: group._id,
      });
    });

    res.json({ message: 'Members added successfully', group });
  } catch (error) {
    console.error('Error adding members to group:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/groups', authenticateToken, async (req, res) => {
  try {
    const groups = await Group.find({ members: req.user.id });
    console.log('Fetched groups:', groups); // Log the fetched groups

    // Return full group details
    res.json(groups);
  } catch (error) {
    console.error('Error fetching groups:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/groups/:groupId', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  try {
    const group = await Group.findById(groupId).lean();
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    res.json(group);
  } catch (error) {
    console.error('Error fetching group:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/groups/:groupId/messages', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  const { content, fileUrl } = req.body;

  if (!content && !fileUrl) {
    return res.status(400).json({ error: 'Message content is required' });
  }

  try {
    const group = await Group.findById(groupId);

    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }

    const message = new Message({
      sender: req.user.id,
      groupId,
      content,
      isGroup: true,
      timestamp: new Date(),
    });

    await message.save();

    // Emit the message to all group members
    io.to(groupId).emit('group_message', {
      sender: req.user.username,
      content: message.content,
      timestamp: message.timestamp,
    });
    console.log(`Message emitted to group ${groupId}:`, {
      sender: req.user.username,
      content: message.content,
      timestamp: message.timestamp,
    });

    res.json({ message: 'Message sent successfully', data: message });
  } catch (error) {
    console.error('Error sending group message:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/groups/:groupId/messages', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  const limit = Math.min(parseInt(req.query.limit) || 30, 100);
  const before = req.query.before ? new Date(req.query.before) : null;

  try {
    const match = { groupId };
    if (before && !isNaN(before.getTime())) {
      match.timestamp = { $lt: before };
    }

    const messagesDesc = await Message.find(match)
      .sort({ timestamp: -1 })
      .limit(limit)
      .lean();

    res.json(messagesDesc.reverse());
  } catch (error) {
    console.error('Error fetching group messages:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/groups/:groupId/last-message', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  try {
    const lastMessage = await Message.findOne({ groupId })
      .sort({ timestamp: -1 })
      .lean();
    if (!lastMessage) {
      return res.json(null);
    }
    res.json(lastMessage);
  } catch (error) {
    console.error('Error fetching last group message:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
/// DELETE /messages/:id  (or POST /messages/delete-many for batch delete)
// Example using Express + MongoDB
// Add a test route to verify server is reachable
app.get('/health', (req, res) => {
  console.log('✅ Health check route hit');
  res.send('OK');
});

app.delete('/messages/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  console.log(`🗑️ Attempting to delete message with ID: ${id}`);

  if (!mongoose.Types.ObjectId.isValid(id)) {
    console.warn(`⚠️ Invalid ObjectId format for ID: ${id}`);
    return res.status(400).json({ error: 'Invalid message ID format' });
  }

  try {
    const deleted = await Message.findByIdAndDelete(id);
    if (!deleted) {
      console.warn(`⚠️ Message with ID ${id} not found`);
      return res.status(404).json({ error: 'Message not found' });
    }

    console.log('✅ Deleted message:', {
      id: deleted._id,
      content: deleted.content,
      fileUrl: deleted.fileUrl,
    });

    res.status(200).json({ message: 'Deleted successfully' });
  } catch (err) {
    console.error(`❌ Error deleting message ID ${id}:`, err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.delete('/messages/delete-many', authenticateToken, async (req, res) => {
  const { ids } = req.body; // DELETE requests can have a body

  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'Message IDs must be a non-empty array' });
  }

  try {
    const result = await Message.updateMany(
      { _id: { $in: ids }, visibleTo: req.user.id },
      { $pull: { visibleTo: req.user.id } }
    );

    // Notify the user's other clients to remove the messages
    io.to(req.user.id).emit('messages_deleted', { messageIds: ids });

    res.json({ success: true, updatedCount: result.nModified });

  } catch (error) {
    console.error('Error soft-deleting messages:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /messages/mark-read (must come before /messages/:id)
// Request body: { user: 'username', otherUser: 'username' }
app.put('/messages/mark-read', authenticateToken, async (req, res) => {
  const { user, otherUser } = req.body;

  if (!user || !otherUser) return res.status(400).json({ error: 'Missing parameters' });

  const roomId = normalizeRoomId(user, otherUser);

  try {
    // Only mark messages as read that haven't been read by this user yet
    const messagesToUpdate = await Message.find({
      roomId,
      sender: { $ne: user }, // Only mark messages NOT sent by this user
      visibleTo: { $in: [user] },
      readBy: { $ne: user },
    });

    if (messagesToUpdate.length === 0) {
      return res.json({ success: true, markedCount: 0 });
    }

    const messageIds = messagesToUpdate.map(msg => msg._id);
    await Message.updateMany(
      { _id: { $in: messageIds } },
      { $addToSet: { readBy: user } }
    );

    const readMessageIds = messageIds.map(id => id.toString());

    // Notify the sender (otherUser) if online that their messages were read
    const senderSocketId = userIdToSocketId[otherUser];
    if (senderSocketId) {
      io.to(senderSocketId).emit('messages_read', {
        reader: user,
        messageIds: readMessageIds,
      });
    }

    res.json({ success: true, markedCount: messageIds.length });
  } catch (error) {
    console.error('Error marking messages as read:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/messages/:id', authenticateToken, async (req, res) => {
  const messageId = req.params.id;
  const { content } = req.body;

  try {
    const updatedMessage = await Message.findByIdAndUpdate(
      messageId,
      { content, edited: true },
      { new: true }
    );

    if (!updatedMessage) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Notify the room that a message was edited
    if (updatedMessage.roomId) {
      io.to(updatedMessage.roomId).emit('message_edited', {
        messageId: updatedMessage._id,
        newContent: updatedMessage.content,
        edited: updatedMessage.edited,
      });
    }

    res.json(updatedMessage);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/users', authenticateToken, async (req, res) => {
  try {
    // Fetch all users except the current user
    const users = await User.find(
      { _id: { $ne: req.user.id } }, // Exclude the current user
      '_id username email' // <-- include _id
    );
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user profile
app.get('/profile/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    console.log(`📋 GET /profile/${userId} - Request from user: ${req.user?.id || 'unknown'}`);
    
    let user;
    
    // Try to find by ObjectId first, then by username
    if (mongoose.Types.ObjectId.isValid(userId)) {
      user = await User.findById(userId, '-password');
    } else {
      // Search by username if not a valid ObjectId
      user = await User.findOne({ username: userId }, '-password');
    }
    
    if (!user) {
      console.log(`❌ User not found: ${userId}`);
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log(`✅ Profile found for user: ${user.username}`);
    res.json(user);
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user profile
app.put('/profile/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const updates = req.body;
    
    // Ensure user can only update their own profile
    if (req.user.id !== userId) {
      return res.status(403).json({ error: 'Cannot update another user\'s profile' });
    }
    
    // Remove sensitive fields that shouldn't be updated via this endpoint
    delete updates.password;
    delete updates.email;
    delete updates.phoneNumber;
    
    // If updating profile picture, add current one to history
    if (updates.profilePicture) {
      const currentUser = await User.findById(userId);
      if (currentUser && currentUser.profilePicture && currentUser.profilePicture !== updates.profilePicture) {
        // Add current profile picture to history if it's not already there
        const history = currentUser.profilePictureHistory || [];
        if (!history.includes(currentUser.profilePicture)) {
          history.unshift(currentUser.profilePicture); // Add to beginning
          // Keep only last 20 profile pictures
          updates.profilePictureHistory = history.slice(0, 20);
        }
      }
    }
    
    // Get the old username before updating
    const currentUser = await User.findById(userId).select('username');
    const oldUsername = currentUser?.username;
    
    const updatedUser = await User.findByIdAndUpdate(userId, updates, { new: true });
    
    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // If username changed, update all messages and conversations
    if (updates.username && oldUsername && oldUsername !== updates.username) {
      console.log(`🔄 Updating messages from ${oldUsername} to ${updates.username}`);
      
      // Update all messages where this user is the sender
      const senderResult = await Message.updateMany(
        { sender: oldUsername },
        { $set: { sender: updates.username } }
      );
      console.log(`📝 Updated ${senderResult.modifiedCount} messages as sender`);
      
      // Update all messages where this user is the receiver
      const receiverResult = await Message.updateMany(
        { receiver: oldUsername },
        { $set: { receiver: updates.username } }
      );
      console.log(`📝 Updated ${receiverResult.modifiedCount} messages as receiver`);
      
      // Update readBy arrays that contain the old username
      const readByResult = await Message.updateMany(
        { readBy: { $in: [oldUsername] } },
        { $set: { "readBy.$[elem]": updates.username } },
        { arrayFilters: [{ "elem": oldUsername }] }
      );
      console.log(`📝 Updated ${readByResult.modifiedCount} readBy arrays`);
      
      // Update visibleTo arrays that contain the old username
      const visibleToResult = await Message.updateMany(
        { visibleTo: { $in: [oldUsername] } },
        { $set: { "visibleTo.$[elem]": updates.username } },
        { arrayFilters: [{ "elem": oldUsername }] }
      );
      console.log(`📝 Updated ${visibleToResult.modifiedCount} visibleTo arrays`);
      
      console.log(`✅ Updated all messages for username change: ${oldUsername} -> ${updates.username}`);
    }

    // Emit profile update to all connected users if username or profile picture changed
    if (updates.username || updates.profilePicture) {
      console.log(`📡 Broadcasting profile update for user: ${updatedUser.username}`);
      io.emit('user_profile_updated', {
        userId: userId,
        username: updatedUser.username,
        profilePicture: updatedUser.profilePicture
      });
    }
    
    res.json(updatedUser);
  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.use((req, res, next) => {
  console.log(`❓ Incoming request: ${req.method} ${req.url}`);
  next();
});

// Start server with socket.io attached
server.listen(port, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});

