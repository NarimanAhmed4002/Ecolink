import { asyncHandler } from '../../utils/error/index.js';
import * as reviewsService from './reviews.service.js';

export const create = asyncHandler(async (req, res) => {
  const review = await reviewsService.createReview(req.user, req.body);
  res.status(201).json({ success: true, data: review });
});

export const list = asyncHandler(async (req, res) => {
  const reviews = await reviewsService.listReviews(req.query);
  res.status(200).json({ success: true, data: reviews });
});

