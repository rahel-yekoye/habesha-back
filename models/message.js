const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true, default: 'Unknown' },
  receiver: { type: String, required: true, default: 'Unknown' },
  roomId: { type: String, default: null },
  groupId: { type: String, default: null },
  content: { type: String, default: '[No Content]' },
  fileUrl: { type: String, default: '' },
  emojis: { type: [String], default: [] },
  reactions: [{ user: String, emoji: String }],
  isGroup: { type: Boolean, default: false },
  isFile: { type: Boolean, default: false },
  deleted: { type: Boolean, default: false },
  edited: { type: Boolean, default: false },
  direction: { type: String, enum: ['incoming', 'outgoing'], default: 'incoming' },
  duration: { type: Number, default: null }, // For voice/video messages in seconds
  readBy: { type: [String], default: [] },    // Array of userIds/usernames
  timestamp: { type: Date, default: Date.now },
  visibleTo: [{ type: String }], // Array of user IDs/usernames who should see this message
  clientId: { type: String, default: null }, // ✅ Add this
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message', default: null },

});

// Expose the auto-generated _id as 'id' in JSON
messageSchema.method('toJSON', function () {
  const { _id, __v, ...object } = this.toObject();
  object.id = _id;
  return object;
});

// Indexes for performance on conversation queries
messageSchema.index({ roomId: 1, timestamp: 1 });
messageSchema.index({ groupId: 1, timestamp: 1 });

module.exports = mongoose.model('Message', messageSchema);
