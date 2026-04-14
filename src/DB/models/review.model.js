import mongoose from 'mongoose';

const { Schema } = mongoose;

const ReviewSchema = new Schema(
  {
    factory: { type: Schema.Types.ObjectId, ref: 'Factory', required: true },
    createdBy: { type: Schema.Types.ObjectId, ref: 'Factory', required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: { type: String, trim: true },
  },
  { timestamps: true }
);

ReviewSchema.index({ factory: 1, createdAt: -1 });

export const Review = mongoose.model('Review', ReviewSchema);
