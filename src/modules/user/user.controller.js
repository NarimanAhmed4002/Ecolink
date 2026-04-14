import { asyncHandler } from '../../utils/error/index.js';
import * as userService from './user.service.js';

export const getProfile = asyncHandler(async (req, res, next) => {
  const user = await userService.getProfile(req.user._id);
  res.status(200).json({ success: true, data: user });
});

export const updateProfile = asyncHandler(async (req, res, next) => {
  const user = await userService.updateProfile(req.user._id, req.body);
  res.status(200).json({ success: true, data: user });
});

export const changePassword = asyncHandler(async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;
  await userService.changePassword(req.user._id, currentPassword, newPassword);
  res.status(200).json({ success: true, message: 'Password updated successfully' });
});
//E:\ECO LINK\ecolink-backend\src\modules\user\user.controller.js