const validateSendMessage = (body) => {
  const { negotiationId, text } = body || {};
  if (!negotiationId) return 'negotiationId is required';
  if (!text || !text.trim()) return 'text is required';
  return null;
};

export { validateSendMessage };

