import { Review } from '../../DB/models/review.model.js';
import { Factory } from '../../DB/models/factory.model.js';
import { ensureFactoryForUser } from '../factories/factories.service.js';

export const createReview = async (user, { factoryId, rating, comment }) => {
  const creator = await ensureFactoryForUser(user);

  const target = await Factory.findById(factoryId);
  if (!target) throw new Error('Factory not found', { cause: 404 });

  const review = await Review.create({
    factory: target._id,
    createdBy: creator._id,
    rating: Number(rating),
    comment,
  });

  return review;
};

export const listReviews = async ({ factoryId }) => {
  const query = {};
  if (factoryId) query.factory = factoryId;
  return await Review.find(query).populate('factory').populate('createdBy').sort({ createdAt: -1 });
};

