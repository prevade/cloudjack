# CloudJack 

### AWS Route53/CloudFront/S3 Vulnerability Assessment Utility

CloudJack assesses AWS accounts for subdomain hijacking vulnerabilities as a result of decoupled Route53 and CloudFront configurations. This vulnerability exists if a Route53 alias references 1) a deleted CloudFront web distribution or 2) an active CloudFront web distribution with deleted CNAME(s).

If this decoupling is discovered by an attacker, they can simply create a CloudFront web distribution and/or CloudFront NAME(s) in their account that match the victim account's Route53 A record host name. Exploitation of this vulnerability results in the ability to spoof the victim's web site content, which otherwise would have been accessed through the victim's account.

CloudJacking video at Austin OWASP May 2018: https://www.youtube.com/watch?v=tMMpK0kd5H8

Requirements:

1. AWS IAM access key ID and corresponding secret key
2. AWS CLI installation configured with profile(s), access key ID(s), and secret key(s) in ~/.aws/credentials

        [default]
        aws_access_key_id=<ACCESS_KEY>
        aws_secret_access_key=<SECRET>

        and/or

        [myprofile]
        aws_access_key_id=<ACCESS_KEY>
        aws_secret_access_key=<SECRET>

3. AWS IAM policy allowing Route53 ListHostedZones and ListResourceRecordSets actions
4. AWS IAM policy allowing CloudFront ListDistributions actions
5. Python and AWS SDK boto3 package
    - pip install boto3

Usage:
    $ python cloudjack.py -o [text|json] -p [profile]

Examples:
   - $ python cloudjack.py -o json -p default
   - $ python cloudjack.py -o text -p default
   - $ python cloudjack.py -o json -p myprofile
   - $ python cloudjack.py -o text -p myprofile

   Wishlist:

   1. Assess S3/CloudFront decoupling
   2. Offensive reconnaissance and exploitation features

Notes:

Python3 now supported. Use cloudjack-p2.py for Python2.

References:

- http://docs.aws.amazon.com/Route53/latest/APIReference/API_ListHostedZones.html
- http://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html
- http://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html
- http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
