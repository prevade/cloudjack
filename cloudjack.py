#!/usr/bin/env python

#    CloudJack: Route53/CloudFront Vulnerability Assessment Utility
#
#    Copyright 2017 Prevade Cybersecurity
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

import argparse
import boto3

def test_CNAME():

        # Initialize Route53 and CloudFront clients
        route53 = boto3.client('route53')
        cloudfront = boto3.client('cloudfront')

        # Initialize local variables
        cname = dname = flag = name = target = None

def test_DNAME():

        # Initialize Route53 and CloudFront clients
        route53 = boto3.client('route53')
        cloudfront = boto3.client('cloudfront')

        # Initialize local variables
        dname = flag = name = target = zoneid = zonetype = None

        # Enumerate and iterate through all Route53 hosted zone ID's
        for hosted_zone in sorted(route53.list_hosted_zones()['HostedZones']):

                zoneid = hosted_zone['Id'].split("/")[2]

                if hosted_zone['Config']['PrivateZone']: zonetype = "Private"
                else: zonetype="Public"

                for resource_record_set in route53.list_resource_record_sets(HostedZoneId=zoneid)['ResourceRecordSets']:

                        # Set flag to zero on each iteration
                        flag = 0

                        # Set name variable to Route53 A record FQDN omitting trailing dot
                        aname = resource_record_set['Name'][:-1]

                        # Set target variable to the Route53 alias FQDN of CloudFront distribution
                        if 'AliasTarget' in resource_record_set and 'DNSName' in resource_record_set['AliasTarget']:

                                target = resource_record_set['AliasTarget']['DNSName'][:-1]

                                if 'cloudfront' in target:

                                        # Enumerate (de-)coupled Route53 alias targets and CloudFront distributions
                                        for item in cloudfront.list_distributions()['DistributionList']['Items']:

                                                # CloudFront distribution ID
                                                distid = item['Id']

                                                # CloudFront disitrbution FQDN
                                                dname = item['DomainName']

                                                # Flag and break if Route53 alias FQDN matches a CloudFront distribution FQDN
                                                if target in dname:
                                                        flag +=1
                                                        break

                                        # Check flag value and print appropriate response
                                        if flag:
                                                print ("[+] Zone:%-20s\tType:%-10s\tHost:%-50s\tAlias:%-25s\tDist:%-15s\tName:%-25s" % (zoneid,zonetype,aname,target,distid,dname))
                                        if not flag:
                                                dname = "=" * 50
                                                print ("[+] Zone:%-20s\tType:%-10s\tHost:%-50s\tAlias:%-25s\tDist:%-15s\tName:%-25s" % (zoneid,zonetype,aname,target,distid,dname))

if __name__ == "__main__":

        parser = argparse.ArgumentParser(add_help=True, description='Route53/CloudFront Vulnerability Assessment Utility')
        parser.add_argument("-t", "--type", action="store", required=True)

        args = vars(parser.parse_args())

        if args['type'] == 'cname': test_CNAME()
        if args['type'] == 'dname': test_DNAME()

#EOF
