export function buildOtpEmailHtml(params: {
  otp: string;
  logoUrl?: string;
}): string {
  const { otp, logoUrl } = params;

  const resolvedLogoUrl =
    logoUrl ||
    'https://via.placeholder.com/150x50/ffffff/00629B?text=IEEE+CUSB';
  console.log('Resolved Logo URL:', resolvedLogoUrl);
  return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IEEE CUSB Verification</title>
    <style>
        body { margin: 0; padding: 0; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f7; color: #51545E; }

        @media only screen and (max-width: 600px) {
            .email-container { width: 100% !important; padding: 20px !important; }
            .otp-code { font-size: 28px !important; letter-spacing: 5px !important; }
        }
    </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f7; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;">

    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f4f4f7; padding: 40px 0;">
        <tr>
            <td align="center">

                <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); overflow: hidden;">

                    <tr>
                        <td style="background-color: #00629B; padding: 40px 0; text-align: center;">
                            <img src="${resolvedLogoUrl}"
                                 alt="IEEE CUSB Logo"
                                 width="150"
                                 style="display: block; margin: 0 auto; max-width: 80%; height: auto; border: 0;">
                        </td>
                    </tr>

                    <tr>
                        <td style="padding: 40px 30px;">
                            <h2 style="color: #333333; font-size: 22px; margin-top: 0; margin-bottom: 20px; text-align: center;">Welcome to the Community!</h2>

                            <p style="font-size: 16px; line-height: 24px; margin-bottom: 20px; color: #51545E;">
                                Hi there,
                            </p>
                            <p style="font-size: 16px; line-height: 24px; margin-bottom: 30px; color: #51545E;">
                                Thank you for joining <strong>IEEE CUSB</strong>. To complete your registration and verify your email address, please use the One-Time Password (OTP) below.
                            </p>

                            <div style="background-color: #E6F0F6; border-radius: 4px; padding: 20px; text-align: center; margin-bottom: 30px; border: 1px dashed #00629B;">
                                <span class="otp-code" style="font-size: 36px; font-weight: bold; color: #00629B; letter-spacing: 8px; display: block;">${otp}</span>
                            </div>

                            <p style="font-size: 14px; color: #d9534f; text-align: center; font-weight: bold; margin-bottom: 30px;">
                                This code will expire in 10 minutes.
                            </p>

                            <p style="font-size: 16px; line-height: 24px; margin-bottom: 0; color: #51545E;">
                                If you did not request this email, please ignore it.
                            </p>
                        </td>
                    </tr>

                    <tr>
                        <td style="background-color: #f4f4f7; padding: 20px; text-align: center; border-top: 1px solid #eaeaec;">
                            <p style="font-size: 12px; color: #999999; margin: 0;">
                                &copy; ${new Date().getFullYear()} IEEE Cairo University Student Branch. All rights reserved.<br>
                            </p>
                        </td>
                    </tr>
                </table>

            </td>
        </tr>
    </table>

</body>
</html>`;
}
