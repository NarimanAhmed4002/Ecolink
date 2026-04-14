import mongoose from 'mongoose';

const { Schema } = mongoose;

const WASTE_STATUS = ['draft', 'available', 'reserved', 'sold', 'archived'];

const WasteSchema = new Schema(
  {
    factory: { type: Schema.Types.ObjectId, ref: 'Factory', required: true },
    category: { type: Schema.Types.ObjectId, ref: 'WasteCategory', required: true },
    title: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    quantity: { type: Number, required: true, min: 0 },
    unit: { type: String, default: 'kg', trim: true },
    price: { type: Number, required: true, min: 0 },
    currency: { type: String, default: 'USD', trim: true },
    images: [{ type: String, trim: true }],
    status: { type: String, enum: WASTE_STATUS, default: 'available' },
  },
  { timestamps: true }
);

export const Waste = mongoose.model('Waste', WasteSchema);
export { WASTE_STATUS };
