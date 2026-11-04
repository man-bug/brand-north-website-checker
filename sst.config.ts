// eslint-disable-next-line @typescript-eslint/triple-slash-reference
/// <reference path="./.sst/platform/config.d.ts" />

export default $config({
    app(input) {
        return {
            name: "website-checker",
            // Nothing here is worth keeping on teardown, and no stage is protected.
            // Should go without saying, but of course, I'd be a lot more careful
            // if this were a real application.
            removal: "remove",
            protect: false,
            home: "aws",
        };
    },
    async run() {
        const { checker } = await import("./infra/checker");
        return checker();
    },
});
