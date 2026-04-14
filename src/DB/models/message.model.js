import mongoose from 'mongoose';

const { Schema } = mongoose;

const MessageSchema = new Schema(
  {
    negotiation: { type: Schema.Types.ObjectId, ref: 'Negotiation', required: true },
    sender: { type: Schema.Types.ObjectId, ref: 'Factory', required: true },
    text: { type: String, required: true, trim: true },
    isRead: { type: Boolean, default: false },
  },
  { timestamps: true }
);

MessageSchema.index({ negotiation: 1, createdAt: 1 });

export const Message = mongoose.model('Message', MessageSchema);
