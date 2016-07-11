#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
module: ec2_vpc_nat_gateway
short_description: Create, delete and describe AWS Managed NAT Gateways.
description:
  - Creates AWS Managed NAT Gateways with option to provide EIP or
    allocate new address.
  - Deletes AWS Managed NAT Gateways with option to release attached EIP.
  - Describe AWS Managed NAT Gateways, either all or with Filters
  - This module does not support updates or tagging as it is a current
    restriction with AWS. It does support idempotency via the client_token.
  - This module support check mode.
version_added: "2.1"
requirements: [ boto3 ]
options:
  subnet_id:
    description:
      - Required when creating a NAT gateway.
    required: false
  eip_address:
    description:
      - An elastic IP already allocated in the AWS account to be used
        by the NAT gateway. This address cannot already by attached to
        another resource. If this option or the allocation_id is not
        specified, an elastic IP will be allocated and attached for you.
    required: false
  allocation_id:
    description:
      - The allocation id of the EIP address. Mutually exclusive to
        eip_address. This id cannot already by attached to
        another resource. If this option or eip_address is not
        specified, an elastic IP will be allocated and attached for you.
    required: false
  state:
    description:
        - present to ensure resource is created.
        - absent to remove resource
    required: false
    default: present
    choices: [ "present", "absent"]
  wait:
    description:
      - When specified, will wait for either available status for state present
        or deleted for state absent. If release_eip is specified during state absent,
        this will automatically be utilised.
    required: false
    default: no
    choices: ["yes", "no"]
  wait_timeout:
    description:
      - Used in conjunction with wait. Number of seconds to wait for status.
        Recommended value of over 2 minutes.
    required: false
    default: 320
  release_eip:
    description:
      - AWS Managed NAT Gateways do not release the elastic IP by default. Specify
        this option if releasing eip is required.
    required: false
  nat_gateway_id:
    description:
      - The ID of the NAT gateway to be removed - used only for state absent
    required: false
  client_token:
    description:
      - Optional unique token to be used during create to ensure idempotency. When 
        specifying this option, ensure you specify the eip_address parameter as well
        otherwise any subsequent runs will fail.
    required: false
author: Karen Cheng(@Etherdaemon), Jon Hadfield (@jonhadfield)
extends_documentation_fragment: aws
'''

EXAMPLES = '''
- name: Create new nat gateway with client token
  ec2_vpc_nat_gateway:
    state: present
    subnet_id: subnet-12345678
    eip_address: 52.1.1.1
    region: ap-southeast-2
    client_token: abcd-12345678
  register: new_nat_gateway

- name: Create new nat gateway allocation-id
  ec2_vpc_nat_gateway:
    state: present
    subnet_id: subnet-12345678
    allocation_id: eipalloc-12345678
    region: ap-southeast-2
  register: new_nat_gateway

- name: Create new nat gateway with when condition
  ec2_vpc_nat_gateway:
    state: present
    subnet_id: subnet-12345678
    eip_address: 52.1.1.1
    region: ap-southeast-2
  register: new_nat_gateway
  when: existing_nat_gateways.result == []


- name: Create new nat gateway and wait for available status
  ec2_vpc_nat_gateway:
    state: present
    subnet_id: subnet-12345678
    eip_address: 52.1.1.1
    wait: yes
    region: ap-southeast-2
  register: new_nat_gateway


- name: Create new nat gateway and allocate new eip
  ec2_vpc_nat_gateway:
    state: present
    subnet_id: subnet-12345678
    wait: yes
    region: ap-southeast-2
  register: new_nat_gateway


- name: Delete nat gateway using discovered nat gateways from facts module
  ec2_vpc_nat_gateway:
    state: absent
    region: ap-southeast-2
    wait: yes
    nat_gateway_id: "{{ item.NatGatewayId }}"
    release_eip: yes
  register: delete_nat_gateway_result
  with_items: "{{ gateways_to_remove.result }}"

- name: Delete nat gateway and wait for deleted status
  ec2_vpc_nat_gateway:
    state: absent
    nat_gateway_id: nat-12345678
    wait: yes
    wait_timeout: 500
    region: ap-southeast-2


- name: Delete nat gateway and release EIP
  ec2_vpc_nat_gateway:
    state: absent
    nat_gateway_id: nat-12345678
    release_eip: yes
    region: ap-southeast-2
'''

RETURN = '''
result:
  description: The result of the create, delete or describe action.
  returned: success
  type: dictionary or a list of dictionaries
'''

try:
    import json
    import botocore
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

import time
import datetime


def date_handler(obj):
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def wait_for_status(client, module, nat_gateway_id, status):
    polling_increment_secs = 15
    max_retries = (module.params.get('wait_timeout') / polling_increment_secs)
    status_achieved = False

    for x in range(0, max_retries):
        try:
            nat_gateway = get_nat_gateways(client, module, nat_gateway_id)[0]
            if nat_gateway['State'] == status:
                status_achieved = True
                break
            else:
                time.sleep(polling_increment_secs)
        except botocore.exceptions.ClientError as e:
            module.fail_json(msg=str(e))

    return status_achieved, nat_gateway


def get_nat_gateways(client, module, nat_gateway_id=None):
    params = dict()
    if nat_gateway_id:
        params['NatGatewayIds'] = [nat_gateway_id]

    existing_gateways = json.loads(json.dumps(client.describe_nat_gateways(**params), default=date_handler))

    return existing_gateways['NatGateways']


def create_nat_gateway(client, module, allocation_id):
    params = dict()
    changed = False
    token_provided = False
    params['SubnetId'] = module.params.get('subnet_id')
    params['AllocationId'] = allocation_id

    if module.params.get('client_token'):
        token_provided = True
        request_time = datetime.datetime.utcnow()
        params['ClientToken'] = module.params.get('client_token')

    if module.check_mode:
        return {'changed': True, 'result': 'Would have created NAT Gateway if not in check mode'}

    try:
        changed = True
        result = client.create_nat_gateway(**params)["NatGateway"]
        if token_provided and (request_time > result['CreateTime'].replace(tzinfo=None)):
            changed = False
        elif module.params.get('wait') and not module.check_mode:
            status_achieved, result = wait_for_status(client, module, result['NatGatewayId'], 'available')
            if not status_achieved:
                module.fail_json(msg='Error waiting for nat gateway to become available - please check the AWS console')
    except botocore.exceptions.ClientError as e:
        if "IdempotentParameterMismatch" in e.message:
            module.fail_json(msg='NAT Gateway does not support update and token has already been provided')
        else:
            module.fail_json(msg=str(e))

    return changed, result


def setup_creation(client, module):
    changed = False
    if not module.params.get('subnet_id'):
        module.fail_json(msg='subnet_id is required for creation')

    if not module.params.get('allocation_id') and not module.params.get('eip_address'):
        allocation_id = allocate_eip_address(client, module)
    elif module.params.get('eip_address'):
        allocation_id = get_eip_address(client, module)
    else:
        allocation_id = module.params.get('allocation_id')

    if module.params.get('client_token'):
        changed, result = create_nat_gateway(client, module, allocation_id)
    else:
        existing_gateways = get_nat_gateways(client, module)
        gateway_found = False
        for gateway in existing_gateways:
            if gateway['NatGatewayAddresses'][0]['AllocationId'] == allocation_id:
                gateway_found = True
                if gateway['SubnetId'] == module.params.get('subnet_id'):
                    result = gateway
                else:
                    module.fail_json(msg='Update of nat_gateway is not allowed.')
                break

        if not gateway_found:
            changed, result = create_nat_gateway(client, module, allocation_id)

    return changed, result


def get_eip_address(client, module):
    params = dict()
    params['PublicIps'] = [module.params.get('eip_address')]
    try:
        allocation = client.describe_addresses(**params)['Addresses'][0]
        if not 'AllocationId' in allocation:
            module.fail_json(msg="EIP provided is a non-VPC EIP, please allocate a VPC scoped EIP")
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))

    return allocation['AllocationId']


def allocate_eip_address(client, module):
    params = dict()
    params['DryRun'] = module.check_mode
    params['Domain'] = 'vpc'
    try:
        new_eip = client.allocate_address(**params)
    except botocore.exceptions.ClientError as e:
        if 'DryRunOperation' in e.message:
            new_eip = {'AllocationId': 'eip-12345678'}
        else:
            module.fail_json(msg=str(e))
    return new_eip['AllocationId']


def release_eip(client, module, allocation_id):
    params = dict()
    params['AllocationId'] = allocation_id
    params['DryRun'] = module.check_mode
    try:
        client.release_address(**params)
    except Exception as e:
        if 'DryRunOperation' not in e.message:
            module.fail_json(msg=str(e))


def setup_removal(client, module):
    params = dict()
    changed = False
    if not module.params.get('nat_gateway_id'):
        module.fail_json(msg='nat_gateway_id is required for removal')
    elif module.check_mode:
        return {'changed': True, 'result': 'Would have deleted NAT Gateway if not in check mode'}
    else:
        params['NatGatewayId'] = module.params.get('nat_gateway_id')
        result = client.delete_nat_gateway(**params)
        changed = True

    if module.params.get('wait') or module.params.get('release_eip'):
        status_achieved, result = wait_for_status(client, module, params['NatGatewayId'], 'deleted')
        if not status_achieved:
            module.fail_json(msg='Error waiting for nat gateway to be removed - please check the AWS console')
        if module.params.get('release_eip'):
            release_eip(client, module, result['NatGatewayAddresses'][0]['AllocationId'])

    return changed, result


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        subnet_id=dict(),
        eip_address=dict(),
        allocation_id=dict(),
        state=dict(default='present', choices=['present', 'absent']),
        wait=dict(type='bool', default=False),
        wait_timeout=dict(type='int', default=320, required=False),
        release_eip=dict(type='bool', default=False),
        nat_gateway_id=dict(),
        client_token=dict(),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ['allocation_id', 'eip_address']
        ]
    )

    # Validate Requirements
    if not HAS_BOTO3:
        module.fail_json(msg='json and botocore/boto3 is required.')

    state = module.params.get('state').lower()

    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    except NameError as e:
        # Getting around the get_aws_connection_info boto reliance for region
        if "global name 'boto' is not defined" in e.message:
            module.params['region'] = botocore.session.get_session().get_config_variable('region')
            if not module.params['region']:
                module.fail_json(msg="Error - no region provided")
        else:
            module.fail_json(msg="Can't retrieve connection information - "+str(e))

    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        ec2 = boto3_conn(module, conn_type='client', resource='ec2', region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except botocore.exceptions.NoCredentialsError, e:
        module.fail_json(msg=str(e))

    #Ensure resource is present
    if state == 'present':
        (changed, results) = setup_creation(ec2, module)
    else:
        (changed, results) = setup_removal(ec2, module)

    module.exit_json(changed=changed, result=json.loads(json.dumps(results, default=date_handler)))


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()