import { asyncHandler } from '../../utils/error/index.js';
import * as cartService from './cart.service.js';

export const getCart = asyncHandler(async (req, res, next) => {
  const result = await cartService.getCart(req.user);
  res.status(200).json({ success: true, data: result });
});

export const addItem = asyncHandler(async (req, res, next) => {
  const item = await cartService.addItem(req.user, req.body.wasteId, req.body.quantity);
  res.status(201).json({ success: true, data: item });
});

export const updateItem = asyncHandler(async (req, res, next) => {
  const item = await cartService.updateItem(req.user, req.params.wasteId, req.body.quantity);
  res.status(200).json({ success: true, data: item });
});

export const removeItem = asyncHandler(async (req, res, next) => {
  const result = await cartService.removeItem(req.user, req.params.wasteId);
  res.status(200).json({ success: true, data: result });
});
