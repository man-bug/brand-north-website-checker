// eslint-disable-next-line @typescript-eslint/triple-slash-reference
/// <reference path="../.sst/platform/config.d.ts" />

// CI authentication for GitHub Actions: one deploy role, trusted by main-branch
// pushes only. The trust subject uses GitHub's immutable repo@ID format for
// repos created after 2026-07-15; slug-based subjects never match. The account
// hosts other projects, so every grant is scoped to this app's resource
// patterns. Auth model and scoping notes: docs/ci.md.

const ACCOUNT_ID = "022499005161";
const GITHUB_OIDC_ARN = `arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com`;
const STATE_BUCKET = "sst-state-mxhnetvbrttm";
const ASSET_BUCKET = "sst-asset-mxhnetvbrttm";

// State keys are <category>/<app>/...; app name is untruncated here.
const STATE_PREFIX = "*/website-checker/*";

// Lambda names truncate at 64 chars and the truncation point varies per
// resource: website-c-, website-check-, website-checke- are all observed.
// The honest shared prefix is website-; a hypothetical future website-*
// project would share these grants (docs/ci.md, Permission scoping).
const APP_PATTERN = "website-*";

// The revalidation events subscriber is the one component named without the
// stage prefix; its suffix changes on recreation.
const SUBSCRIBER_PATTERN = "WebsiteCheckerRevalidationEventsSubscriber*";

function trust(sub: string) {
    return JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                Effect: "Allow",
                Principal: { Federated: GITHUB_OIDC_ARN },
                Action: "sts:AssumeRoleWithWebIdentity",
                Condition: {
                    StringEquals: {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:sub": sub,
                    },
                },
            },
        ],
    });
}

function deployPolicy() {
    return JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                Sid: "StsIdentity",
                Effect: "Allow",
                Action: "sts:GetCallerIdentity",
                Resource: "*",
            },
            {
                Sid: "StateObjects",
                Effect: "Allow",
                Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                Resource: `arn:aws:s3:::${STATE_BUCKET}/${STATE_PREFIX}`,
            },
            {
                Sid: "StateBucketList",
                Effect: "Allow",
                Action: "s3:ListBucket",
                Resource: `arn:aws:s3:::${STATE_BUCKET}`,
                // Unconditioned: Pulumi lists with arbitrary prefixes.
            },
            {
                Sid: "SiteBuckets",
                Effect: "Allow",
                Action: [
                    "s3:CreateBucket",
                    "s3:DeleteBucket",
                    "s3:ListBucket",
                    "s3:GetBucketAcl", "s3:PutBucketAcl",
                    "s3:GetBucketCors", "s3:PutBucketCors", "s3:DeleteBucketCors",
                    "s3:GetBucketLifecycle", "s3:PutBucketLifecycle", "s3:DeleteBucketLifecycle",
                    "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
                    "s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock",
                    "s3:GetBucketOwnershipControls", "s3:PutBucketOwnershipControls",
                    "s3:DeleteBucketOwnershipControls",
                    "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                ],
                Resource: [`arn:aws:s3:::${APP_PATTERN}`, `arn:aws:s3:::${APP_PATTERN}/*`],
            },
            {
                // Function code zips for the WebsiteChecker* components.
                Sid: "AssetCodeObjects",
                Effect: "Allow",
                Action: [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    // Pulumi stamps default tags on writes, so PutObject needs it.
                    "s3:PutObjectTagging",
                    "s3:GetObjectTagging",
                    "s3:AbortMultipartUpload",
                    "s3:ListMultipartUploadParts",
                ],
                Resource: `arn:aws:s3:::${ASSET_BUCKET}/assets/WebsiteChecker*`,
            },
            {
                Sid: "SstBootstrap",
                Effect: "Allow",
                Action: ["ssm:GetParameter", "ssm:PutParameter"],
                Resource: `arn:aws:ssm:*:${ACCOUNT_ID}:parameter/sst/bootstrap`,
            },
            {
                Sid: "SstPassphraseRead",
                Effect: "Allow",
                Action: "ssm:GetParameter",
                Resource: `arn:aws:ssm:*:${ACCOUNT_ID}:parameter/sst/passphrase/website-checker/*`,
            },
            {
                Sid: "IamPassAppRoles",
                Effect: "Allow",
                Action: "iam:PassRole",
                Resource: `arn:aws:iam::${ACCOUNT_ID}:role/${APP_PATTERN}`,
            },
            {
                Sid: "IamManageAppRoles",
                Effect: "Allow",
                Action: [
                    "iam:CreateRole",
                    "iam:DeleteRole",
                    "iam:GetRole",
                    "iam:UpdateRole",
                    "iam:UpdateAssumeRolePolicy",
                    "iam:PutRolePolicy",
                    "iam:GetRolePolicy",
                    "iam:DeleteRolePolicy",
                    "iam:ListRolePolicies",
                    "iam:ListAttachedRolePolicies",
                ],
                Resource: `arn:aws:iam::${ACCOUNT_ID}:role/${APP_PATTERN}`,
            },
            {
                Sid: "IamAttachLambdaManagedPolicy",
                Effect: "Allow",
                Action: ["iam:AttachRolePolicy", "iam:DetachRolePolicy"],
                Resource: `arn:aws:iam::${ACCOUNT_ID}:role/${APP_PATTERN}`,
                Condition: {
                    ArnEquals: {
                        // The one policy SST hardcodes onto the roles it creates.
                        "iam:PolicyARN": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                    },
                },
            },
            {
                Sid: "LambdaAppFunctions",
                Effect: "Allow",
                Action: [
                    "lambda:CreateFunction",
                    "lambda:UpdateFunctionCode",
                    "lambda:UpdateFunctionConfiguration",
                    "lambda:DeleteFunction",
                    "lambda:GetFunction",
                    "lambda:GetFunctionConfiguration",
                    "lambda:GetFunctionCodeSigningConfig",
                    "lambda:ListVersionsByFunction",
                    "lambda:GetPolicy",
                    "lambda:AddPermission",
                    "lambda:RemovePermission",
                    "lambda:GetFunctionUrlConfig",
                    "lambda:UpdateFunctionUrlConfig",
                    // Lambda@Edge replication for the origin signer.
                    "lambda:EnableReplication",
                    // Pulumi's lambda.Invocation seeds the revalidation table.
                    "lambda:InvokeFunction",
                ],
                Resource: [
                    `arn:aws:lambda:*:${ACCOUNT_ID}:function:${APP_PATTERN}`,
                    `arn:aws:lambda:*:${ACCOUNT_ID}:function:${SUBSCRIBER_PATTERN}`,
                ],
            },
            {
                // Mapping ARNs are UUIDs with no name component.
                Sid: "LambdaEventSourceMappings",
                Effect: "Allow",
                Action: [
                    "lambda:CreateEventSourceMapping",
                    "lambda:UpdateEventSourceMapping",
                    "lambda:DeleteEventSourceMapping",
                    "lambda:GetEventSourceMapping",
                ],
                Resource: "*",
            },
            {
                // Distribution and policy ARNs are random IDs with no name
                // component; narrow with tag conditions if the account grows.
                Sid: "CloudFrontBroad",
                Effect: "Allow",
                Action: ["cloudfront:*"],
                Resource: "*",
            },
            {
                // KV store ARNs are UUIDs, untaggable through SST.
                Sid: "CloudFrontKvStore",
                Effect: "Allow",
                Action: ["cloudfront-keyvaluestore:*"],
                Resource: `arn:aws:cloudfront::${ACCOUNT_ID}:key-value-store/*`,
            },
            {
                Sid: "DynamoAppTables",
                Effect: "Allow",
                Action: [
                    "dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:DescribeTable",
                    "dynamodb:UpdateTable", "dynamodb:UpdateTimeToLive", "dynamodb:DescribeTimeToLive",
                    "dynamodb:DescribeContinuousBackups", "dynamodb:UpdateContinuousBackups",
                ],
                Resource: `arn:aws:dynamodb:*:${ACCOUNT_ID}:table/${APP_PATTERN}`,
            },
            {
                Sid: "SqsAppQueues",
                Effect: "Allow",
                Action: [
                    "sqs:CreateQueue", "sqs:DeleteQueue", "sqs:GetQueueUrl",
                    "sqs:GetQueueAttributes", "sqs:SetQueueAttributes",
                ],
                Resource: `arn:aws:sqs:*:${ACCOUNT_ID}:${APP_PATTERN}`,
            },
            {
                Sid: "LogsApp",
                Effect: "Allow",
                Action: [
                    "logs:CreateLogGroup",
                    "logs:DeleteLogGroup",
                    "logs:PutRetentionPolicy",
                ],
                Resource: [
                    `arn:aws:logs:*:${ACCOUNT_ID}:log-group:/aws/lambda/${APP_PATTERN}`,
                    // The subscriber's log group follows its unprefixed name.
                    `arn:aws:logs:*:${ACCOUNT_ID}:log-group:/aws/lambda/${SUBSCRIBER_PATTERN}`,
                ],
            },
        ],
    });
}

export function ciOidc() {
    const deploy = new aws.iam.Role(
        "github-website-checker-deploy",
        {
            name: "github-website-checker-deploy",
            description:
                "Deploys the website-checker SST app. Trusts main-branch pushes only.",
            assumeRolePolicy: trust(
                "repo:man-bug@136141397/brand-north-website-checker@1446140408:ref:refs/heads/main"
            ),
        },
        { protect: true }
    );
    new aws.iam.RolePolicy(
        "github-website-checker-deploy-policy",
        {
            name: "github-website-checker-deploy-policy",
            role: deploy.name,
            policy: deployPolicy(),
        },
        { protect: true }
    );
}
