import { asyncHandler } from '../../utils/error/index.js';
import * as negotiationsService from './negotiations.service.js';

export const create = asyncHandler(async (req, res) => {
  const negotiation = await negotiationsService.createNegotiation(req.user, req.body.wasteId);
  res.status(201).json({ success: true, data: negotiation });
});

export const listMine = asyncHandler(async (req, res) => {
  const negotiations = await negotiationsService.listMyNegotiations(req.user);
  res.status(200).json({ success: true, data: negotiations });
});

export const getOne = asyncHandler(async (req, res) => {
  const negotiation = await negotiationsService.getNegotiationById(req.user, req.params.id);
  res.status(200).json({ success: true, data: negotiation });
});

