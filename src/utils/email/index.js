// Email utilities - to be implemented (e.g. nodemailer, SendGrid)
export const sendEmail = async ({ to, subject, html }) => {
  // TODO: implement
  console.log('sendEmail stub:', { to, subject });
  return true;
};

export const sendVerificationEmail = async (user, link) => {
  // TODO: implement
  return sendEmail({
    to: user.email,
    subject: 'Verify your email',
    html: `Verify: ${link}`,
  });
};
