export const verifyEmailTemplate = (url: string) => {
    return `<!doctype html>
<html>
    <head>
        <meta charset="UTF-8" />
        <title>Email Verification</title>
    </head>
    <body
        style="
            font-family:
                JetBrains Mono,
                Menlo,
                monospace;
        "
    >
        <table cellspacing="0" cellpadding="0" style="width: 100%; background-color: #fff">
            <tr>
                <td style="border-radius: 10px; box-shadow: 0 4px 8px #c2dfe3">
                    <table
                        width="100%"
                        cellspacing="0"
                        cellpadding="0"
                        style="border-bottom: 0.5px solid #c2dfe3"
                    >
                        <tr>
                            <td style="padding: 20px; text-align: center">
                                <strong style="font-size: xx-large">auth-saas</strong>
                            </td>
                        </tr>
                    </table>

                    <table cellspacing="0" cellpadding="0">
                        <tr>
                            <td style="padding: 20px">
                                <div>
                                    <strong style="font-size: large">Email verification</strong>
                                    <p>
                                        Thanks for signing up! Click the button below to verify your
                                        email address.
                                    </p>
                                </div>

                                <div style="text-align: center; margin-top: 15px">
                                    <a
                                        href="${url}"
                                        style="
                                            display: inline-block;
                                            padding: 10px 20px;
                                            background-color: #00a6fb;
                                            color: #fff;
                                            text-decoration: none;
                                            border-radius: 5px;
                                        "
                                    >
                                        Verify your Email
                                    </a>
                                </div>

                                <p style="margin-top: 15px; color: grey; text-align: center">
                                    If having trouble with the button? Copy the link below and paste
                                    into your browser.
                                </p>

                                <div
                                    style="
                                        border: 1px dashed;
                                        border-radius: 5px;
                                        padding: 10px;
                                        margin-top: 15px;
                                    "
                                >
                                    <strong>Verification link:</strong>
                                    <br />
                                    <a href="${url}" style="text-decoration: none"> ${url} </a>
                                </div>

                                <p style="color: grey; margin-top: 15px">
                                    🔒 Do not share this link with anyone. If you did not create any
                                    account, safe to ignore this email.
                                </p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
</html>`;
};
