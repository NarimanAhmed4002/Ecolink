const validateUpdateProfile = (body) => {
  const { fullName } = body || {};
  if (fullName !== undefined && (!fullName || !fullName.trim())) return 'Name cannot be empty';
  return null;
};

const validateChangePassword = (body) => {
  const { currentPassword, newPassword } = body || {};
  if (!currentPassword) return 'Current password is required';
  if (!newPassword) return 'New password is required';
  if (newPassword.length < 6) return 'New password must be at least 6 characters';
  return null;
};

export { validateUpdateProfile, validateChangePassword };
//E:\ECO LINK\ecolink-backend\src\modules\user\user.service.js