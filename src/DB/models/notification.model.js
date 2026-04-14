import mongoose from 'mongoose';

const { Schema } = mongoose;

const NOTIFICATION_TYPES = ['general', 'order', 'negotiation', 'message', 'waste'];

const NotificationSchema = new Schema(
  {
    factory: { type: Schema.Types.ObjectId, ref: 'Factory', required: true },
    type: { type: String, enum: NOTIFICATION_TYPES, default: 'general' },
    title: { type: String, trim: true },
    message: { type: String, required: true, trim: true },
    data: { type: Schema.Types.Mixed },
    isRead: { type: Boolean, default: false },
  },
  { timestamps: true }
);

NotificationSchema.index({ factory: 1, createdAt: -1 });

export const Notification = mongoose.model('Notification', NotificationSchema);
export { NOTIFICATION_TYPES };
