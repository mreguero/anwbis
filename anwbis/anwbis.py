#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import re
import os
import json
import time
import urllib
import hashlib
import argparse
import ConfigParser

import webbrowser
from colorama import Fore, Back, Style

import requests # "pip install requests"
from requests.packages.urllib3 import disable_warnings

from boto import ec2
from boto.sts import STSConnection # AWS Python SDK--"pip install boto"
from boto.iam import IAMConnection

#             __          ___     _  _____
#     /\      \ \        / / |   (_)/ ____|
#    /  \   _ _\ \  /\  / /| |__  _| (___
#   / /\ \ | '_ \ \/  \/ / | '_ \| |\___ \
#  / ____ \| | | \  /\  /  | |_) | |____) |
# /_/    \_\_| |_|\/  \/   |_.__/|_|_____/
#
#          Amazon Account Access

version = '1.5.0'

parser = argparse.ArgumentParser(description='AnWbiS: AWS Account Access')
parser.add_argument('--version', action='version', version='%(prog)s'+version)
parser.add_argument('--project', '-p', required=False, action='store',
                    help=('MANDATORY (if you are not using --iam_master_group,'
                          ' --iam_policy and --iam_delegated_role): Project to'
                          ' connect'),
                    default=False)
parser.add_argument('--env', '-e', required=False, action='store',
                    help=('MANDATORY (if you are not using --iam_master_group, '
                          '--iam_policy and --iam_delegated_role): '
                          'Set environment'),
                    default=False,
                    choices=['dev', 'pre', 'prepro', 'pro', 'sbx',
                             'val', 'corp', 'qa', 'staging', 'demo', 'piloto'])
parser.add_argument('--role', '-r', required=False, action='store',
                    help='Set role to use', default=False,
                    choices=['developer', 'devops', 'user',
                             'admin', 'audit', 'contractor'])
parser.add_argument('--contractor', '-c', required=False, action='store',
                    help='Set role to use with contractor policies',
                    default=False)
parser.add_argument('--externalid', '-ext', required=False, action='store',
                    help='Set External-ID to use with contractor policies',
                    default=False)
parser.add_argument('--region', required=False, action='store',
                    help='Set region for EC2', default=False,
                    choices=['eu-west-1', 'us-east-1', 'us-west-1'])
parser.add_argument('--nomfa', required=False, action='store_true',
                    help='Disables Multi-Factor Authenticacion', default=False)
parser.add_argument('--refresh', required=False, action='store_true',
                    help='Refresh token even if there is a valid one',
                    default=False)
parser.add_argument('--browser', '-b', required=False, action='store',
                    help='Set browser to use', default=False,
                    choices=['firefox','chrome','link','default', 'chromium'])
parser.add_argument('--list', '-l', required=False, action='store',
                    help='List available instances', default=False,
                    choices=['all', 'bastion'])
parser.add_argument('--profile', '-P', required=False, action='store',
                    help = 'Optional: IAM credentials profile to use.',
                    default=False)
parser.add_argument('--duration', type=int, required=False, action='store',
                    help='Optional: Token Duration. Default=3600', default=3600)
parser.add_argument('--iam_master_group', required=False, action='store',
                    help=('MANDATORY (if you are not using -p -e and -r flags):'
                          ' Master account group name to use'), default=False)
parser.add_argument('--iam_policy', required=False, action='store',
                    help=('MANDATORY (if you are not using -p -e and -r flags):'
                          ' IAM Policy to use'), default=False)
parser.add_argument('--iam_delegated_role', required=False, action='store',
                    help=('MANDATORY (if you are not using -p -e and -r flags):'
                          ' IAM delegated role to use'), default=False)
parser.add_argument('--from_ec2_role', required=False, action='store_true',
                    help=('Optional: use IAM role credentials stored in EC2 '
                          'instead of users '
                          '(advice: combine it with externalid)'),
                    default=False)
parser.add_argument('--get_session', required=False, action='store_true',
                    help='Optional: use STS get_session_token)', default=False)
parser.add_argument('--stdout', required=False, action='store_true',
                    help=('Optional: get export commands to set '
                          'environment variables'), default=False)
parser.add_argument('--teleport', '-t', required=False, action='store',
                    help='Teleport to instance', default=False)
parser.add_argument('--filter', '-f', required=False, action='store',
                    help='Filter instance name', default=False)
parser.add_argument('--goodbye', '-g', required=False, action='store_true',
                    help=('There are no easter eggs in this code, '
                          'but AnWbiS can say goodbye'), default=False)
parser.add_argument('--verbose', '-v', action='store_true',
                    help='prints verbosely', default=False)
parser.add_argument('--project-tag', required=False, action='store',
                    help='Optional: Project tag for filtering instances',
                    default='')
parser.add_argument('--bastion-tag', required=False, action='store',
                    help='Optional: Bastion tag for filtering instances',
                    default='Bastion')
parser.add_argument('--name-tag', required=False, action='store',
                    help='Optional: Name tag for filtering instances',
                    default='')


args = parser.parse_args()


# CLI parser

def verbose(msg):
    if args.verbose:
        print(Fore.BLUE + ''.join(map(str, (msg))))
        print(Fore.RESET + Back.RESET + Style.RESET_ALL)

def colormsg(msg,mode):
    print("")
    if mode == 'ok':
        print(Fore.GREEN + '[ OK ] ' + ''.join(map(str, (msg))))
        print(Fore.RESET + Back.RESET + Style.RESET_ALL)
    if mode == 'error':
        print(Fore.RED + '[ ERROR ] ' + ''.join(map(str, (msg))))
        print(Fore.RESET + Back.RESET + Style.RESET_ALL)
    if mode == 'normal':
        print(Fore.WHITE + ''.join(map(str, (msg))))
        print(Fore.RESET + Back.RESET + Style.RESET_ALL)

def sha256(m):
    return hashlib.sha256(m).hexdigest()

def config_line(header, name, detail, data):
    return header + ", " + name + ", " + detail + ", " + data

def config_line_policy(header, name, detail, data):
    verbose("===== " + header + ":  " + name + ":  " + detail + "=====")
    verbose(data)
    verbose("=========================================================")
    return config_line(header, name, detail, sha256(data))

def output_lines(lines):
    lines.sort()
    for line in lines:
        print(line)

def list_function(list_instances, access_key, session_key, session_token, region, filter_name):

    try:
        ec2_conn = ec2.connect_to_region(region,
                                         aws_access_key_id=access_key,
                                         aws_secret_access_key=session_key,
                                         security_token=session_token)
    except Exception as e:
        colormsg("There was an error connecting to EC2", "error")
        verbose(e)
        exit(1)

    reservations = ec2_conn.get_all_reservations(filters={"tag:Name" : "*"+filter_name+"*"})

    bastions = []

    try:
        if len(reservations) > 0:
            if list_instances == 'all' or list_instances == 'bastion':
                layout = "{!s:60} {!s:15} {!s:15} {!s:15} {!s:15}"
                headers = ["Name", "Project", "Bastion", "IP Address",
                           "Instance-Id", "Status"]
                colormsg(region+":", "normal")
                print(layout.format(*headers))

            for reservation in reservations:
                for instance in reservation.instances:
                    if instance.state == "running":
                        if instance.ip_address is None:
                            ip = instance.private_ip_address
                        else:
                            ip = instance.ip_address

                        tags = instance.tags[args.project_tag] if args.project_tag in instance.tags else "N/A"
                        if list_instances == 'all' and args.bastion_tag not in instance.tags:
                            print(layout.format(instance.tags['Name'],
                                                tags,
                                                'N/A',
                                                ip,
                                                instance.id,
                                                instance.state)
                                 )
                        elif list_instances == 'all' or list_instances == 'bastion' and args.bastion_tag in instance.tags:
                            print(layout.format(instance.tags['Name'],
                                                tags,
                                                instance.tags[args.bastion_tag],
                                                ip,
                                                instance.id,
                                                instance.state))
                            bastions.append(ip)
                        elif list_instances == 'teleport' and args.bastion_tag in instance.tags and instance.tags[args.bastion_tag].lower() == 'true':
                            bastions.append(ip)

            return bastions
        else:
            colormsg("There are no instances for your project in the region "+region, "error")
            exit(1)
    except Exception as e:
        colormsg("There was an error while listing EC2 instances", "error")
        verbose(e)
        exit(1)


class Anwbis(object):
    disable_warnings()

    #Runs all the functions
    def __init__(self, args):
        self.args = args
        self.role = 'developer'
        self.profile_name = None
        self.region = 'eu-west-1'
        self.project = None
        self.env = None
        self.browser = None
        self.token_expiration = None
        self.session_token_expiration = None
        self.externalid = None

        self.validate_args()
        token = self.token()
        self.access_key = token['access_key']
        self.session_key = token['session_key']
        self.session_token = token['session_token']
        self.controller()

    def _set_role(self):
        if self.args.role:
            if self.args.role == 'contractor' and not self.args.contractor:
                colormsg ("When using role contractor you must provide --contractor (-c) flag with the contractor policy to asume", "error")
                exit(1)
            elif self.args.role == 'contractor' and self.args.contractor and not self.args.externalid:
                colormsg ("When using role contractor you must provide --externalid (-ext) code with the ExternalID to use", "error")
                exit(1)
            elif self.args.role == 'contractor' and self.args.contractor and self.args.externalid:
                self.role = self.args.role+'-'+self.args.contractor
                verbose("Asuming contractor role: "+ self.role)
            else:
                self.role = self.args.role
        elif self.args.iam_delegated_role:
            self.role = self.args.iam_delegated_role

    def _set_profile(self):

        if self.args.profile:
            self.profile_name = self.args.profile

    def _set_region(self):
        if self.args.region:
            self.region = self.args.region
        else:
            self.region = 'eu-west-1'

    def _set_project(self):
        if self.args.project:
            project = self.args.project
            self.project = project.lower()
            verbose("Proyect: " + self.project)

    def _set_env(self):
        if self.args.env:
            env = self.args.env
            self.env = env.lower()
            verbose("Environment: "+self.env)

    def _set_browser(self):
        if self.args.browser:
            self.browser = self.args.browser

    def _set_expirations(self):
        # Max token duration = 1h, session token = 8h

        if self.args.duration > 3600:
            self.token_expiration = 3600
            if self.args.get_session:
                if self.args.duration > 28800:
                    self.session_token_expiration = 28800
        elif self.args.duration < 900:
            self.token_expiration = 900
            if self.args.get_session:
                self.session_token_expiration = self.token_expiration
        else:
            self.token_expiration = self.args.duration
            if self.args.get_session and not self.args.duration:
                self.session_token_expiration = self.token_expiration
            else:
                self.session_token_expiration = 28800

    def _set_externalid(self):
        if self.args.externalid:
            self.externalid = self.args.externalid


    def validate_args(self):
        if not self.args.project or not self.args.env:
            if not self.args.iam_master_group or not self.args.iam_policy or not self.args.iam_delegated_role and not self.args.from_ec2_role:
                colormsg("You must provide either -p and -e flags or --iam_master_group, --iam_policy and --iam_delegated_role to use Anwbis", "error")
                exit(1)
            elif self.args.from_ec2_role and not self.args.iam_delegated_role:
                colormsg("When using credentials stored in EC2 roles you must use either -p and -e flags or --iam_delegated_role to use Anwbis", "error")
                exit(1)

        self._set_role()
        self._set_profile()
        self._set_region()
        self._set_project()
        self._set_env()
        self._set_browser()
        self._set_expirations()
        self._set_externalid()


    def token(self):
        # Welcome
        if self.args.verbose:
            print(""
                  "            __          ___     _  _____\n"
                  "    /\      \ \        / / |   (_)/ ____|\n"
                  "   /  \   _ _\ \  /\  / /| |__  _| (___\n"
                  "  / /\ \ | '_ \ \/  \/ / | '_ \| |\___ \\\n"
                  " / ____ \| | | \  /\  /  | |_) | |____) |\n"
                  "/_/    \_\_| |_|\/  \/   |_.__/|_|_____/\n")

        print("Amazon Account Access {version}\n".format(version=version))

        if self.args.profile:
            iam_connection = IAMConnection(profile_name=self.args.profile)
        else:
            iam_connection = IAMConnection()
        try:
            if self.args.from_ec2_role:
                request_url = "http://169.254.169.254/latest/meta-data/iam/info/"
                r = requests.get(request_url)
                profilearn = json.loads(r.text)["InstanceProfileArn"]
                profileid = json.loads(r.text)["InstanceProfileId"]
                profilename = json.loads(r.text)["InstanceProfileArn"].split('/')[1]
                role_session_name = profilename
            else:
                role_session_name = iam_connection.get_user().get_user_response.get_user_result.user.user_name
        except Exception as e:
            colormsg ("There was an error retrieving your session_name. Check your credentials", "error")
            verbose(e)
            exit(1)

        #account_id=iam_connection.get_user()['get_user_response']['get_user_result']['user']['arn'].split(':')[4]
        try:
            if self.args.from_ec2_role:
                account_id = profilearn = json.loads(r.text)["InstanceProfileArn"].split(':')[4]
                account_id_from_user = account_id
                role_name_from_user = profilename
            else:
                account_id = iam_connection.get_user().get_user_response.get_user_result.user.arn.split(':')[4]
        except Exception as exc:
            colormsg("There was an error retrieving your account id. Check your credentials", "error")
            verbose(exc)
            exit(1)

        # Regexp for groups and policies. Set the policy name used by your organization

        if self.project and self.env:
            if not self.args.from_ec2_role:
                group_name = 'corp-'+self.project+'-master-'+self.role
                policy_name = 'Delegated_Roles'
                role_filter = self.env+'-'+self.project+'-delegated-'+self.role
            else:
                group_name = 'IAM EC2 ROLE'
                policy_name = 'Delegated_Roles'
                role_filter = self.env+'-'+self.project+'-delegated-'+self.role

        # Get rid of the standard for using another policies or group names
        elif self.args.from_ec2_role and self.args.iam_delegated_role:
            role_filter = self.args.iam_delegated_role
            # Fix references to project, env and role in .anwbis file for non-standard use
            self.role = role_filter
            self.project = group_name
            self.env = "ec2-role"
        elif self.args.iam_master_group and self.args.iam_policy and self.args.iam_delegated_role:
            group_name = self.args.iam_master_group
            policy_name = self.args.iam_policy
            role_filter = self.args.iam_delegated_role
            # Fix references to project, env and role in .anwbis file for non-standard use
            self.role = role_filter
            self.project = group_name
            self.env = policy_name


        # Step 1: Prompt user for target account ID and name of role to assume

        # IAM groups
        verbose("Getting IAM group info:")
        delegated_policy = []
        group_policy = []
        delegated_arn = []

        try:
            if not self.args.from_ec2_role:
                policy = iam_connection.get_group_policy(group_name, policy_name)
            else:
                #policy = iam_connection.get_instance_profile(profilename)
                policy = iam_connection.get_role_policy(profilename, policy_name)
        except Exception as exc:
            colormsg("There was an error retrieving your group policy. Check your credentials, group_name and policy_name", "error")
            verbose(exc)
            exit(1)

        if not self.args.from_ec2_role:
            policy = policy.get_group_policy_response.get_group_policy_result.policy_document
            policy = urllib.unquote(policy)
            group_policy.append(config_line_policy("iam:grouppolicy", group_name, policy_name, policy))

        else:
            policy = policy.get_role_policy_response.get_role_policy_result.policy_document
            policy = urllib.unquote(policy)
            group_policy.append(config_line_policy("iam:grouppolicy", group_name, policy_name, policy))

        output_lines(group_policy)

        # Format policy and search by role_filter

        policy = re.split('"', policy)

        for i in policy:
            result_filter = re.search(role_filter, i)
            if result_filter:
                delegated_arn.append(i)

        if len(delegated_arn) == 0:
            if self.role and self.project:
                colormsg("Sorry, you are not authorized to use the role {} for project {}".format(self.role, self.project), "error")
                exit(1)
            else:
                colormsg("Sorry, you are not authorized to use the role "+role_filter, "error")
                exit(1)

        elif len(delegated_arn) == 1:
            account_id_from_user = delegated_arn[0].split(':')[4]
            role_name_from_user = delegated_arn[0].split('/')[1]

        else:
            colormsg("There are two or more policies matching your input", "error")
            exit(1)


        colormsg("You are authenticated as " + role_session_name, "ok")

        #MFA
        if not self.args.nomfa:
            mfa_devices_r = iam_connection.get_all_mfa_devices(role_session_name)
            if  mfa_devices_r.list_mfa_devices_response.list_mfa_devices_result.mfa_devices:
                mfa_serial_number = mfa_devices_r.list_mfa_devices_response.list_mfa_devices_result.mfa_devices[0].serial_number
            else:
                colormsg("You don't have MFA devices associated with our user", "error")
                exit(1)
        else:
            mfa_serial_number = "arn:aws:iam::"+account_id+":mfa/"+role_session_name

        # Create an ARN out of the information provided by the user.
        role_arn = "arn:aws:iam::" + account_id_from_user + ":role/"
        role_arn += role_name_from_user

        # Connect to AWS STS and then call AssumeRole. This returns temporary security credentials.
        if self.args.profile:
            sts_connection = STSConnection(profile_name=self.args.profile)
        else:
            sts_connection = STSConnection()

        # Assume the role
        if not self.args.nomfa:
            verbose("Assuming role "+ role_arn+ " using MFA device " + mfa_serial_number + "...")
            if self.project:
                colormsg("Assuming role {role} from project {project} using MFA device from user {session_name} ...".format(role=self.role, project=self.project, session_name=role_session_name), "normal")
            elif self.args.iam_delegated_role:
                colormsg("Assuming role {role} using MFA device from user {session_name} ...".format(role=self.role, session_name=role_session_name), "normal")
        else:
            verbose("Assuming role "+ role_arn+ "...")
            if self.project:
                colormsg("Assuming role {role} from project {project} from user {session_name} ...".format(role=self.role, project=self.project, session_name=role_session_name), "normal")
            elif self.args.iam_delegated_role:
                colormsg("Assuming role {role} from user {session_name} ...".format(role=self.role, session_name=role_session_name), "normal")
        if self.args.get_session:
            sts_token = self.get_session_token(sts_connection, role_arn, mfa_serial_number, role_session_name)
        else:
            if os.path.isfile(os.path.expanduser('~/.anwbis')):

                with open(os.path.expanduser('~/.anwbis')) as json_file:
                    root_json_data = json.load(json_file)
                    json_file.close()

                    if self.project in root_json_data and self.env in root_json_data[self.project] and self.role in root_json_data[self.project][self.env]:
                        json_data = root_json_data[self.project][self.env][self.role]
                        self.access_key = json_data["access_key"]
                        self.session_token = json_data["session_token"]
                        self.session_key = json_data["session_key"]
                        self.region = json_data['region']
                        anwbis_last_timestamp = json_data["anwbis_last_timestamp"]

                        #check if the token has expired
                        if int(time.time()) - int(anwbis_last_timestamp) > self.token_expiration or self.args.refresh:

                            verbose("token has expired")
                            sts_token = self.get_sts_token(sts_connection, role_arn, mfa_serial_number, role_session_name)

                        else:
                            verbose("token has not expired, trying to login...")

                        self.login_to_fedaccount(json_data["role_session_name"])
                        sts_token = {'access_key':json_data["access_key"], 'session_key':json_data["session_key"], 'session_token': json_data["session_token"], 'role_session_name': json_data["role_session_name"]}

                    else:
                        sts_token = self.get_sts_token(sts_connection, role_arn, mfa_serial_number, role_session_name)
            else:
                #print ".anwbis configuration file doesnt exists"
                verbose("role is " +  self.role)
                sts_token = self.get_sts_token(sts_connection, role_arn, mfa_serial_number, role_session_name)
        return sts_token

    def controller(self):


        if self.args.list:
            list_instances = self.args.list
            if self.args.filter:
                filter_name = self.args.filter
        else:
            list_instances = 'none'

        if self.args.teleport:
            teleport_instance = self.args.teleport
            if self.args.filter:
                filter_name = self.args.filter
        else:
            teleport = 'none'

        if self.args.list:
            list_function(list_instances,
                          self.access_key,
                          self.session_key,
                          self.session_token,
                          self.region, filter_name)

        # Teleport parser for connecting to bastion

        if self.args.teleport:
            bastions = list_function('teleport',
                                     self.access_key,
                                     self.session_key,
                                     self.session_token,
                                     self.region,
                                     filter_name)
            if len(bastions) == 0:
                colormsg("Sorry, there are no bastions to connect in project {project} for the environment {env}".format(project=self.project, env=self.env), "error")
            elif len(bastions) == 1:
                for bastion in bastions:
                    print(bastion)
            else:
                colormsg("There are more than one bastion in project {project} for the environment {env}".format(project=self.project, env=self.env), "normal")
                #list_function('bastion')
                colormsg("You can connect to the desired bastion using -t <IP> (--teleport <IP>)", "normal")

    def save_credentials(self, role_session_name, project_name, environment_name,
                         role_name, local_file_path="~/.anwbis"):
        """
        Persists temporal credentials in a local file
        :param access_key: Access Key Id
        :param session_key: Secret Key
        :param session_token: Temporal token
        :param role_session_name: Session role name
        :param project_name: Project
        :param environment_name: Environment (dev, pro, pre...)
        :param role_name: Role name
        :param region: Default region
        """


        if os.path.isfile(os.path.expanduser(local_file_path)):

            with open(os.path.expanduser(local_file_path), 'r') as json_file:
                json_file.seek(0)
                root_json_data = json.load(json_file)
                json_file.close()

            with open(os.path.expanduser(local_file_path), 'w+') as json_file:
                if project_name not in root_json_data:
                    project = root_json_data[project_name] = {}
                if environment_name not in root_json_data[project_name]:
                    environment = project[environment_name] = {}
                if role_name not in root_json_data[project_name][environment_name]:
                    role_data = environment[role_name] = {}

                role_data["anwbis_last_timestamp"] = str(int(time.time()))
                role_data["access_key"] = self.access_key
                role_data["role_session_name"] = role_session_name
                role_data["session_key"] = self.session_key
                role_data["session_token"] = self.session_token
                role_data["region"] = self.region
                json.dump(root_json_data, json_file)
        else:
            with open(os.path.expanduser(local_file_path), 'w+') as json_file:
                data = {
                    project_name: {
                        environment_name: {
                            role_name: {
                                "anwbis_last_timestamp": str(int(time.time())),
                                "access_key": self.access_key,
                                "role_session_name": role_session_name,
                                "session_key": self.session_key,
                                "session_token": self.session_token,
                                "region": self.region
                            }
                        }
                    }
                }
                json.dump(data, json_file)

    def get_sts_token(self, sts_connection, role_arn, mfa_serial_number, role_session_name):
        try:

            if not self.args.nomfa:
                mfa_token = raw_input("Enter the MFA code: ")
                if self.args.externalid:
                    assumed_role_object = sts_connection.assume_role(
                        role_arn=role_arn,
                        role_session_name=role_session_name,
                        duration_seconds=self.token_expiration,
                        mfa_serial_number=mfa_serial_number,
                        mfa_token=mfa_token,
                        external_id=self.externalid
                    )
                else:
                    assumed_role_object = sts_connection.assume_role(
                        role_arn=role_arn,
                        role_session_name=role_session_name,
                        duration_seconds=self.token_expiration,
                        mfa_serial_number=mfa_serial_number,
                        mfa_token=mfa_token
                    )

            else:
                mfa_token = None
                if self.args.externalid:
                    assumed_role_object = sts_connection.assume_role(
                        role_arn=role_arn,
                        role_session_name=role_session_name,
                        duration_seconds=self.token_expiration,
                        external_id=self.externalid
                    )
                else:
                    assumed_role_object = sts_connection.assume_role(
                        role_arn=role_arn,
                        role_session_name=role_session_name,
                        duration_seconds=self.token_expiration,
                    )

        except Exception as e:
            colormsg("There was an error assuming role", "error")
            verbose(e)
            exit(1)

        colormsg("Assumed the role successfully", "ok")

        # Format resulting temporary credentials into a JSON block using
        # known field names.

        self.access_key = assumed_role_object.credentials.access_key
        self.session_key = assumed_role_object.credentials.secret_key
        self.session_token = assumed_role_object.credentials.session_token

        self.login_to_fedaccount(role_session_name)

        self.save_credentials(role_session_name, self.project, self.env, self.role)

        #and save them on the CLI config file .aws/credentials

        self.save_cli_credentials('-'.join([self.project, self.env, self.role]))

        if self.args.stdout:
            print("")
            print("If you want to use your credentials from the environment with an external Tool (for instance, Terraform), you can use the following instructions:")
            print("WARNING: If you use it in the same shell as anwbis exported variables takes precedence over the .aws/credentials, so use it carefully")
            print("")
            print("export AWS_ACCESS_KEY_ID='%s'" % self.access_key)
            print("export AWS_SECRET_ACCESS_KEY='%s'" % self.session_key)
            print("export AWS_SESSION_TOKEN='%s'" % self.session_token)
            print("export AWS_DEFAULT_REGION='%s'" % self.region)
            print("")

        return { 'access_key': self.access_key,
                'session_key': self.session_key,
                'session_token': self.session_token,
                'role_session_name': role_session_name }

    def get_session_token(self, sts_connection, role_arn, mfa_serial_number, role_session_name):
        try:

            if not self.args.nomfa:
                mfa_token = raw_input("Enter the MFA code: ")
                sts_session = sts_connection.get_session_token(
                    duration=self.session_token_expiration,
                    mfa_serial_number=mfa_serial_number,
                    mfa_token=mfa_token
                )

                session_sts_connection = STSConnection(aws_access_key_id=sts_session.access_key,
                                                       aws_secret_access_key=sts_session.secret_key,
                                                       security_token=sts_session.session_token)

                if self.args.externalid:
                    assumed_role_object = session_sts_connection.assume_role(
                        role_arn=role_arn,

                        role_session_name=role_session_name,
                        duration_seconds=self.token_expiration,
                        external_id=self.externalid
                    )
                else:
                    assumed_role_object = session_sts_connection.assume_role(
                        role_arn=role_arn,
                        role_session_name=role_session_name,
                        duration_seconds=self.token_expiration,
                    )
            else:
                colormsg("When using get_session you must use MFA", "error")
                exit(1)

        except Exception as e:
            colormsg("There was an error assuming role", "error")
            verbose(e)
            exit(1)

        colormsg("Assumed the role successfully", "ok")

        # Format resulting temporary credentials into a JSON block using
        # known field names.
        self.access_key = sts_session.access_key
        self.session_key = sts_session.secret_key
        self.session_token = sts_session.session_token
        expiration = sts_session.expiration

        self.login_to_fedaccount(role_session_name)

        if not self.args.profile:
            credential_profile = 'default'
        else:
            credential_profile = self.args.profile

        self.save_credentials(role_session_name,
                              'corp',
                              'session',
                              credential_profile)


        #and save them on the CLI config file .aws/credentials

        self.save_cli_credentials('-'.join(['corp',
                                            'session',
                                            credential_profile])
                                 )

        if self.args.stdout:
            print("\nIf you want to use your credentials from the environment "
                  "with an external Tool (for instance, Terraform), "
                  "you can use the following instructions:")
            print("WARNING: If you use it in the same shell as anwbis exported "
                  "variables takes precedence over the .aws/credentials, "
                  "so use it carefully\n")
            print("export AWS_ACCESS_KEY_ID='%s'" % self.access_key)
            print("export AWS_SECRET_ACCESS_KEY='%s'" % self.session_key)
            print("export AWS_SESSION_TOKEN='%s'" % self.session_token)
            print("export AWS_DEFAULT_REGION='%s'" % self.region)
            print("Expiration='%s'" % expiration)
            print("")

        return {'access_key': self.access_key,
                'session_key': self.session_key,
                'session_token': self.session_token,
                'role_session_name': role_session_name}

    def save_cli_credentials(self, section_name):
        config = ConfigParser.RawConfigParser()
        home = os.path.expanduser("~")
        basedir = os.path.dirname(home+'/.aws/credentials')
        if not os.path.exists(basedir):
            os.makedirs(basedir)
        if not os.path.isfile(home+'/.aws/credentials'):
            verbose("There is no ~/.aws/credentials "
                    "(probably using an EC2 instance profile.) "
                    "Creating credentials file...")
            open(home+'/.aws/credentials', 'a').close()
        config.read(os.path.expanduser('~/.aws/credentials'))

        if not config.has_section(section_name):
            config.add_section(section_name)

        config.set(section_name, 'aws_access_key_id', self.access_key)
        config.set(section_name, 'aws_secret_access_key', self.session_key)
        config.set(section_name, 'aws_session_token', self.session_token)
        config.set(section_name, 'aws_security_token', self.session_token)
        config.set(section_name, 'region', self.region)

        # Writing our configuration file to 'example.cfg'
        with open(os.path.expanduser('~/.aws/credentials'), 'wb') as configfile:
            config.write(configfile)

    def login_to_fedaccount(self, role_session_name):

        temp_credentials = {"sessionId": self.access_key,
                            "sessionKey": self.session_key,
                            "sessionToken": self.session_token}
        json_temp_credentials = json.dumps(temp_credentials)

        # Make a request to the AWS federation endpoint to get a sign-in
        # token, passing parameters in the query string. The call requires an
        # Action parameter ('getSigninToken') and a Session parameter (the
        # JSON string that contains the temporary credentials that have
        # been URL-encoded).
        request_parameters = "?Action=getSigninToken"
        request_parameters += "&Session="
        request_parameters += urllib.quote_plus(json_temp_credentials)
        request_url = "https://signin.aws.amazon.com/federation"
        request_url += request_parameters
        r = requests.get(request_url)

        # Get the return value from the federation endpoint--a
        # JSON document that has a single element named 'SigninToken'.
        sign_in_token = r.json()["SigninToken"]

        # Create the URL that will let users sign in to the console using
        # the sign-in token. This URL must be used within 15 minutes of when the
        # sign-in token was issued.
        quoted_url = urllib.quote_plus("https://console.aws.amazon.com/")
        request_parameters = ("?Action=login"
                              "&Issuer={session_name}"
                              "&Destination={console_url}"
                              "&SigninToken={signintoken}")
        request_url = "https://signin.aws.amazon.com/federation"
        request_url += request_parameters.format(session_name=role_session_name,
                                                 console_url=quoted_url,
                                                 signintoken=sign_in_token)

        # Easter Egg: Say Hello
        if self.args.goodbye:
            print("\n"
                  "        .' ;' ;             ;''''.\n"
                  "        ;| ; |;            ;;    ;\n"
                  "        ;| ; |;            ;;.   ;\n"
                  "        ;  ~~~~',,,,,,,    '. '  ;\n"
                  "        ;    -A       ;      ';  ;\n"
                  "        ;       .....'        ;   ;\n"
                  "        ;      _;             ;   ;\n"
                  "        ;   __(o)__.          ;   ;\n"
                  "       .;  '\--\\--\        .'    ;\n"
                  "     .'\ \_.._._\\......,.,.;     ;\n"
                  "  .''   |       ;   ';      '    .'\n"
                  " ;      |      .'    ;..,,.,,,,.'\n"
                  " ;      |    .'  ...'\n"
                  " '.     \  .'   ,'  \\\n"
                  "   '.    ;'   .;     \\\n"
                  "     '.      .'      '-'\n"
                  "       '..  .'\n"
                  "          '''\n"
                  "\n"
                  "  Thanks for using AnWbiS. Goodbye!\n"
                  "\n")

        # Use the browser to sign in to the console using the
        # generated URL.
        browsers = {"chrome_path": '/usr/bin/google-chrome %s',
                    "firefox_path": '/usr/bin/firefox %s',
                    "chromium_path": '/usr/bin/chromium-browser %s'}

        browser_path = browsers.get("{}_path".format(self.browser), None)
        if browser_path is not None:
            try:
                webbrowser.get(browser_path).open(request_url, new=0)
            except Exception as e:
                colormsg("There was an error while open your browser", "error")
                verbose(e)
                exit(1)
        else:
            if self.browser == 'default':
                try:
                    webbrowser.open(request_url)
                except Exception as e:
                    colormsg("There was an error while open your browser", "error")
                    verbose(e)
                    exit(1)
            elif self.browser == 'link':
                colormsg(request_url, "normal")


def main():
    Anwbis(args)
