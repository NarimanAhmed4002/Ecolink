import mongoose from 'mongoose';

const { Schema } = mongoose;

const NEGOTIATION_STATUS = ['open', 'agreed', 'rejected', 'closed'];

const NegotiationSchema = new Schema(
  {
    buyer: { type: Schema.Types.ObjectId, ref: 'Factory', required: true },
    seller: { type: Schema.Types.ObjectId, ref: 'Factory', required: true },
    waste: { type: Schema.Types.ObjectId, ref: 'Waste', required: true },
    status: { type: String, enum: NEGOTIATION_STATUS, default: 'open' },
    lastMessageAt: { type: Date },
    agreedPrice: { type: Number, min: 0 },
    currency: { type: String, default: 'USD', trim: true },
  },
  { timestamps: true }
);

NegotiationSchema.index({ buyer: 1, seller: 1, waste: 1 });

export const Negotiation = mongoose.model('Negotiation', NegotiationSchema);
export { NEGOTIATION_STATUS };
