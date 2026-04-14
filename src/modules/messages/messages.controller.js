import { asyncHandler } from '../../utils/error/index.js';
import * as messagesService from './messages.service.js';

export const send = asyncHandler(async (req, res) => {
  const message = await messagesService.sendMessage(req.user, req.body);
  res.status(201).json({ success: true, data: message });
});

export const list = asyncHandler(async (req, res) => {
  const messages = await messagesService.listMessages(req.user, req.query.negotiationId);
  res.status(200).json({ success: true, data: messages });
});

