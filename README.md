# CloudJack » AWS Subdomain Hijacking

### Route53/CloudFront Vulnerability Assessment Utility

CloudJack assesses AWS accounts for subdomain hijacking vulnerabilities due to decoupled Route53 and CloudFront configurations. This vulnerability exists only if a Route53 alias references a deleted CloudFront distribution or an active CloudFront distribution with a deleted CNAME.

If this decoupling is discovered, an attacker can create their own CloudFront disutribution and/or CNAME that matches the victim's Route53 A record host name value that corresponds to the alias target. Exploitation of this vulnerability permits the attacker to impersonate the victim's content which would otherwise be delivered via the victim's CloudFront distribution.

More information at https://www.slideshare.net/BryanMcAninch/cloud-jacking
