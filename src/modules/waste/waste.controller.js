import { asyncHandler } from '../../utils/error/index.js';
import * as wasteService from './waste.service.js';

export const create = asyncHandler(async (req, res) => {
  const waste = await wasteService.createWaste(req.user, req.body);
  res.status(201).json({ success: true, data: waste });
});

export const list = asyncHandler(async (req, res) => {
  const wastes = await wasteService.listWaste(req.query);
  res.status(200).json({ success: true, data: wastes });
});

export const getOne = asyncHandler(async (req, res) => {
  const waste = await wasteService.getWasteById(req.params.id);
  res.status(200).json({ success: true, data: waste });
});

export const update = asyncHandler(async (req, res) => {
  const waste = await wasteService.updateWaste(req.user, req.params.id, req.body);
  res.status(200).json({ success: true, data: waste });
});

export const remove = asyncHandler(async (req, res) => {
  const result = await wasteService.deleteWaste(req.user, req.params.id);
  res.status(200).json({ success: true, data: result });
});

