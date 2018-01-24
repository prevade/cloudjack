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
#
#    Usage: $ python cloudjack.py [type: TEXT|json]
#    ex1: $ python cloudjack.py
#    ex2: $ python cloudjack.py json

import boto3
import json
import sys

try:
    output_type = sys.argv[1]
except IndexError:
    output_type = 'text'

def cloudjack(output_type):

        # in ~/.aws/credentials, you need
        # [cloud-jacker]
        # aws_access_key_id=foo
        # aws_secret_access_key=bar
        session    = boto3.Session(profile_name='cloud-jacker') # the name of the section in ~/.aws/credentials

        # Initialize Route53 and CloudFront clients
        route53    = session.client('route53')
        cloudfront = session.client('cloudfront')

        # Initialize local variables
        aname = cname = dname = target = None
        cflag = dflag = flag = None
        zoneid = zonetype = None
        #results = output_type = None
        results = None
        results = []

        #output_type = 'text'

        # Enumerate and iterate through all Route53 hosted zone ID's
        for hosted_zone in sorted(route53.list_hosted_zones()['HostedZones']):

                zoneid = hosted_zone['Id'].split("/")[2]

                if hosted_zone['Config']['PrivateZone']: zonetype = "Private"
                else: zonetype="Public"

                for resource_record_set in route53.list_resource_record_sets(HostedZoneId=zoneid)['ResourceRecordSets']:

                        # Set distribution flag to zero on each iteration
                        dflag = 0

                        # Set name variable to Route53 A record FQDN omitting trailing dot
                        aname = resource_record_set['Name'][:-1]

                        # Set target variable to the Route53 alias FQDN of CloudFront distribution
                        if 'AliasTarget' in resource_record_set and 'DNSName' in resource_record_set['AliasTarget']:

                                target = resource_record_set['AliasTarget']['DNSName'][:-1]

                                if 'cloudfront' in target:

                                        # Set CNAME flag to zero on each iteration
                                        cflag = 0

                                        # Enumerate (de-)coupled Route53 alias targets and CloudFront distributions
                                        for item in cloudfront.list_distributions()['DistributionList']['Items']:

                                                # CloudFront distribution ID
                                                distid = item['Id']

                                                # CloudFront disitrbution FQDN
                                                dname = item['DomainName']

                                                # Flag and break if Route53 alias FQDN matches a CloudFront distribution FQDN
                                                if target in dname:
                                                        dflag +=1

                                                if item['Aliases']['Quantity']:

                                                        for cname in item['Aliases']['Items']:

                                                                if cname in aname:
                                                                        cflag+=1
                                                                        break
                                                if dflag and cflag:
                                                        flag = '+'
                                                if dflag and not cflag:
                                                        flag = '-'
                                                        cname = "FAIL"
                                                if not dflag:
                                                        flag = '-'
                                                        cname = dname = "FAIL"

                                                data = {
                                                    'zoneid':   zoneid,
                                                    'zonetype': zonetype,
                                                    'aname':    aname,
                                                    'cname':    cname,
                                                    'dname':    dname,
                                                    'target':   target,
                                                    'distid':   distid,
                                                    'flag':     flag,
                                                   }

                                                results.append(data)
                display(results, output_type)


def display(results, output_type):
    if output_type == 'json':
        print json.dumps(results, indent=4, sort_keys=True)
    else:
        for result in results:
            #py3 print ("{flag} Zone: {zoneid}\tType: {zonetype}\tHost: {aname}\tAlias: {target}\tDist: {distid}\tName: {dname}\tCNAME: {cname}".format_map(result))
            print ("[{flag}] Zone: {zoneid}\tType: {zonetype}\tHost: {aname}\tAlias: {target}\tDist: {distid}\tName: {dname}\tCNAME: {cname}".format(**result))

if __name__ == "__main__":
        cloudjack(output_type)
