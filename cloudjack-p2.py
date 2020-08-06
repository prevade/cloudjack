#!/usr/bin/env python

#    CloudJack: Route53/CloudFront Vulnerability Assessment Utility
#
#    Copyright 2018 Prevade Cybersecurity
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    Usage: $ python cloudjack.py

import boto3
import json
import sys
import argparse


def init_clients(sess):

    r = sess.client('route53')
    c = sess.client('cloudfront')
    s = sess.client('s3')

    return (r, c, s)


def main():

    __title__ = "CloudJack"
    __version__ = "1.0.4"

    msg = __title__ + " v" + __version__

    banner = """
  oooooooo8 o888                              oooo ooooo                      oooo        
o888     88  888   ooooooo  oooo  oooo   ooooo888   888   ooooooo    ooooooo   888  ooooo 
888          888 888     888 888   888 888    888   888   ooooo888 888     888 888o888    
888o     oo  888 888     888 888   888 888    888   888 888    888 888         8888 88o   
 888oooo88  o888o  88ooo88    888o88 8o  88ooo888o  888  88ooo88 8o  88ooo888 o888o o888o
                                                  8o888
"""

    parser = argparse.ArgumentParser(add_help=False, formatter_class=argparse.RawTextHelpFormatter, epilog=msg)

    parser.add_argument('-h', '--help', dest='show_help', action='store_true', help='Display this message and exit\n\n')
    parser.add_argument('-o', '--output', help='Output format, defaults to JSON', type=str)
    parser.add_argument('-p', '--profile', help='AWS profile, defaults to [default]', type=str)
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output, display banner and real-time analysis updates')
    parser.set_defaults(show_help='False')

    args = parser.parse_args()

    if args.show_help is True:
        print ''
        print parser.format_help()
        sys.exit(0)

    if args.profile:
        profile = args.profile
    else:
        profile = "default"

    if args.output:
        output = args.output
    else:
        output = "json"

    if args.verbose:
        print("%s \n\t\t\t%s\n" % (banner, msg))

    session = boto3.Session(profile_name=profile)

    # Initialize Route53, CloudFront, and S3 boto3 clients

    (route53, cloudfront, s3) = init_clients(session)

    # Initialize local variables
    aname = cname = dname = target = cflag = dflag = status = zoneid = zonetype = None
    results = []

    # Enumerate and iterate through all Route53 hosted zone ID's
    for hosted_zone in sorted(route53.list_hosted_zones()['HostedZones']):

        # Parse ZoneID result
        zoneid = hosted_zone['Id'].split("/")[2]

        if args.verbose:
            print ("Analyzing Route53 ZoneID %s...\n" % zoneid)

        # Determine if zone is public or private for informational purposes
        if hosted_zone['Config']['PrivateZone']:
            zonetype = "Private"
        else:
            zonetype = "Public"

        # Iterate through all Route53 resource records sets
        for resource_record_set in route53.list_resource_record_sets(HostedZoneId=zoneid)['ResourceRecordSets']:

            # Set distribution flag to zero on each iteration
            dflag = 0

            # Set name variable to Route53 A record FQDN and truncate trailing dot
            aname = resource_record_set['Name'][:-1]

            # Set target variable to the Route53 alias FQDN of CloudFront distribution
            if 'AliasTarget' in resource_record_set and 'DNSName' in resource_record_set['AliasTarget']:

                # Set target variable and truncate string
                target = resource_record_set['AliasTarget']['DNSName'][:-1]

                # Determine if the target is a cloudfront distribution
                if 'cloudfront' in target:

                    # Set CNAME flag to zero on each iteration
                    cflag = 0

                    # Enumerate de-coupled Route53 alias targets and CloudFront distributions
                    for item in cloudfront.list_distributions()['DistributionList']['Items']:

                        # CloudFront distribution ID
                        distid = item['Id']

                        # CloudFront disitrbution FQDN
                        dname = item['DomainName']

                        # Flag and break if Route53 alias FQDN matches a CloudFront distribution FQDN
                        if target in dname:
                            dflag += 1

                            # Flag and break if Route53 A record matches a CloudFront CNAME
                            if item['Aliases']['Quantity']:

                                # Determine if the Route53 alias matches a corresponding CloudFront CNAME
                                for cname in item['Aliases']['Items']:

                                    if cname in aname:
                                        cflag += 1
                                        break

                    # A pair of flags indicates Route53 and CloudFront are NOT decoupled
                    if dflag and cflag:
                        status = 'PASS'
                    if dflag and not cflag:
                        status = 'FAIL'
                        cname = None
                    if not dflag:
                        status = 'FAIL'
                        cname = dname = None
                    # Create a JSON object with Route53 and CloudFront attributes
                    data = {
                        'zoneid':   zoneid,
                        'zonetype': zonetype,
                        'aname':    aname,
                        'cname':    cname,
                        'dname':    dname,
                        'target':   target,
                        'distid':   distid,
                        'status':   status,
                    }
                    # Push each iteration onto results array
                    results.append(data)

    if output == "text":
        for result in results:
            print ("Status: {status}\tZone: {zoneid}\tType: {zonetype}\tHost: {aname}\tAlias: {target}\tDist: {distid}\tName: {dname}\tCNAME: {cname}".format(
                **result))
    else:
        print json.dumps(results, indent=4, sort_keys=True)


if __name__ == "__main__":
    main()
