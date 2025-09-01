const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  phoneNumber: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profilePicture: { type: String, default: null },
  profilePictureHistory: [{ type: String }],
  status: { type: String, default: 'Hey there! I am using Chat App' },
  lastSeen: { type: Date, default: Date.now },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);