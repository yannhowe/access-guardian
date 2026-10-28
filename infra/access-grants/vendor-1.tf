# Case AG-20261028-10.
# Requester: Yann, for vendor-1.
# Expiry: 2026-11-04T12:59:00Z (20:59 SGT).
# Delete this file after expiry.
#
# Inline policy on the existing IAM user vendor-1.
# This file does not create or import the user.
# The Allow stops at the expiry. The Deny has no time condition.

resource "aws_iam_user_policy" "vendor_1" {
  name = "ag-20261028-10"
  user = "vendor-1"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListBucketsUntilExpiry"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = "arn:aws:s3:::*"
        Condition = {
          DateLessThan = {
            "aws:CurrentTime" = "2026-11-04T12:59:00Z"
          }
        }
      },
      {
        Sid      = "GetObjectsUntilExpiry"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::*/*"
        Condition = {
          DateLessThan = {
            "aws:CurrentTime" = "2026-11-04T12:59:00Z"
          }
        }
      },
      {
        Sid    = "DenyExcludedBuckets"
        Effect = "Deny"
        Action = "s3:*"
        Resource = [
          "arn:aws:s3:::ag-demo-assets-a-10281729",
          "arn:aws:s3:::ag-demo-assets-a-10281729/*",
        ]
      },
    ]
  })
}
