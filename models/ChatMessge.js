import mongoose from 'mongoose';

const chatMessageSchema = new mongoose.Schema({
  city: { type: mongoose.Schema.Types.ObjectId, ref: 'City', required: true },
  groupName: { type: String, required: true}, // e.g. 'Open Chat' or 'Places', 'Food', 'Hotels'
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String },
  media: [{ type: String }], // urls to images/videos
  emoji: { type: String },
}, { timestamps: true });

export default mongoose.models.ChatMessage || mongoose.model('ChatMessage', chatMessageSchema);
