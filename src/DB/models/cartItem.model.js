import mongoose from 'mongoose';

const { Schema } = mongoose;

const CartItemSchema = new Schema(
  {
    cart: { type: Schema.Types.ObjectId, ref: 'ShoppingCart', required: true },
    waste: { type: Schema.Types.ObjectId, ref: 'Waste', required: true },
    quantity: { type: Number, required: true, min: 0 },
  },
  { timestamps: true }
);

CartItemSchema.index({ cart: 1, waste: 1 }, { unique: true });

export const CartItem = mongoose.model('CartItem', CartItemSchema);
