import { asyncHandler } from '../../utils/error/index.js';
import * as ordersService from './orders.service.js';

export const create = asyncHandler(async (req, res) => {
  const result = await ordersService.createOrder(req.user, req.body);
  res.status(201).json({ success: true, data: result });
});

export const listMine = asyncHandler(async (req, res) => {
  const orders = await ordersService.listMyOrders(req.user);
  res.status(200).json({ success: true, data: orders });
});

export const getOne = asyncHandler(async (req, res) => {
  const result = await ordersService.getOrderById(req.user, req.params.id);
  res.status(200).json({ success: true, data: result });
});

