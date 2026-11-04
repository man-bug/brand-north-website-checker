import chromium from "@sparticuz/chromium";
import puppeteer from "puppeteer-core";

// @sparticuz/chromium is Linux-only; local dev uses the system Chrome
// install instead. Lambda presence check is the easiest discriminator.
const inLambda = Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

export async function launchBrowser() {
    if (inLambda) {
        return puppeteer.launch({
            args: [...chromium.args, "--disable-dev-shm-usage"],
            executablePath: await chromium.executablePath(),
            headless: true,
            defaultViewport: { width: 1280, height: 720 },
        });
    }
    return puppeteer.launch({
        channel: "chrome",
        headless: true,
        defaultViewport: { width: 1280, height: 720 },
    });
}
