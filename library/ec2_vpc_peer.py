#!/usr/bin/python
#
DOCUMENTATION = """
---
module: ec2_vpc_peer
short_description: create or remove a peering connection between to ec2 VPCs.
description:
    -
options:
  vpc_id:
    description:
      - VPC id of the requesting VPC.
    required: true
  vpc_peer_id:
    description:
      - VPC id of the accepting VPC.
    required: true
  state:
    description:
      - Create or delete the peering connection.
    required: false
    default: present
    choices: ['present', 'absent']
  wait_timeout:
    description:
      - How long to wait for peering connection state changes, in seconds
    required: false
    default: 10
  update_routes:
    description:
      - Whether to update the VPC route tables to add the peering connection.
    required: false
    default: true
  region:
    description:
      - The AWS region to use.  Must be specified if ec2_url is not used. If not specified then the value of the EC2_REGION environment variable, if any, is used.
    required: false
    default: null
    aliases: ['aws_region', 'ec2_region']
  aws_secret_key:
    description:
      - AWS secret key. If not set then the value of the AWS_SECRET_KEY environment variable is used.
    required: false
    default: None
    aliases: ['ec2_secret_key', 'secret_key']
  aws_access_key:
    description:
      - AWS access key. If not set then the value of the AWS_ACCESS_KEY environment variable is used.
    required: false
    default: None
    aliases: ['ec2_access_key', 'access_key']

requirements: [ "boto" ]
"""

import sys
import time

try:
    import boto.ec2
    import boto.vpc
    import boto.exception
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

def wait_for_connection_state(peering_conn, status_code, timeout):
    """
    Wait until the peering connection has transition into the required state.
    Return True if the state is reached before timing out and False if the wait
    times out.
    """
    wait_end = time.time() + timeout
    while wait_end > time.time():
        peering_conn.update()
        if peering_conn.status_code == status_code:
            return True
        time.sleep(1)
    return False

def update_vpc_routes(vpc_conn, peering_conn_id, src_vpc_info, dest_vpc_info):
    """
    Update the route tables in the source VPC to point to the destination VPC.
    """
    subnet = vpc_conn.get_all_subnets(filters={'cidr': src_vpc_info.cidr_block,
                                               'vpc_id': src_vpc_info.vpc_id})
    if len(subnet) != 1:
        return False

    subnet = subnet[0]
    rt = vpc_conn.get_all_route_tables(filters=
                                       {'vpc_id': src_vpc_info.vpc_id,
                                        'association.subnet_id': subnet.id})
    if len(rt) != 1:
        return False

    rt = rt[0]
    replace = False
    for route in rt.routes:
        if route.destination_cidr_block == dest_vpc_info.cidr_block:
            replace = True
            break

    if replace:
        vpc_conn.replace_route(rt.id, dest_vpc_info.cidr_block,
                               vpc_peering_connection_id=peering_conn_id)
    else:
        vpc_conn.create_route(rt.id, dest_vpc_info.cidr_block,
                              vpc_peering_connection_id=peering_conn_id)
    return True

def update_routes(module, vpc_conn, peering_conn):
    """
    Update the route tables to account for the peering connection.
    """
    if not module.params.get('update_routes'):
        return

    update_vpc_routes(vpc_conn, peering_conn.id,
                      peering_conn.requester_vpc_info,
                      peering_conn.accepter_vpc_info)
    update_vpc_routes(vpc_conn, peering_conn.id,
                      peering_conn.accepter_vpc_info,
                      peering_conn.requester_vpc_info)

def create_peer_connection(module, vpc_conn):
    """
    Creates a VPC peeering connection.

    module: Ansible module object
    vpc_conn: authenticated VPCConnection connection object
    vpc_id: id of the requesting VPC
    vpc_peer_id: id of the accepting VPC
    timeout: how long, in seconds, to wait for connection state changes.

    Returns a tuple containing the peering connection id and a boolean
    indicating whether any changes were made.
    """
    vpc_id = module.params.get('vpc_id')
    vpc_peer_id = module.params.get('vpc_peer_id')
    timeout = module.params.get('wait_timeout')

    peering_conns = vpc_conn.get_all_vpc_peering_connections(filters=[
        ('requester-vpc-info.vpc-id', vpc_id),
        ('accepter-vpc-info.vpc-id', vpc_peer_id)])
    for peering_conn in peering_conns:
        if peering_conn.status_code == 'active':
            return (peering_conn.id, False)
        if peering_conn.status_code == 'pending-acceptance':
            vpc_conn.accept_vpc_peering_connection(peering_conn.id)
            result = wait_for_connection_state(peering_conn, 'active', timeout)
            if result:
                update_routes(module, vpc_conn, peering_conn)
                return (peering_conn.id, True)
            else:
                module.fail_json(msg='VPC peering connection with id ' +
                                 peering_conn.id + ' could not be ' +
                                 'accepted.')

    peering_conn = vpc_conn.create_vpc_peering_connection(vpc_id, vpc_peer_id)
    wait_for_connection_state(peering_conn, 'pending-acceptance', timeout)

    vpc_conn.accept_vpc_peering_connection(peering_conn.id)
    wait_for_connection_state(peering_conn, 'active', timeout)

    update_routes(module, vpc_conn, peering_conn)
    return (peering_conn.id, True)

def delete_peer_connection(module, vpc_conn):
    """
    Deletes a VPC peering connection

    module: Ansible module object
    vpc_conn: authenticated VPCConnection connection object
    vpc_id: id of the requesting VPC
    vpc_peer_id: id of the accepting VPC

    Returns a list of the peering connections that have been deleted.
    """
    vpc_id = module.params.get('vpc_id')
    vpc_peer_id = module.params.get('vpc_peer_id')

    peering_conns = vpc_conn.get_all_vpc_peering_connections(filters=[
        ('requester-vpc-info.vpc-id', vpc_id),
        ('accepter-vpc-info.vpc-id', vpc_peer_id)])
    removed_conns = []
    for peering_conn in peering_conns:
        if peering_conn.status_code == 'active':
            if vpc_conn.delete_vpc_peering_connection(peering_conn.id):
                removed_conns.append(peering_conn.id)
            else:
                module.fail_json(msg="VPC peering connection with id " +
                                 peering_conn.id + " could not be " +
                                 "deleted")
    return removed_conns

def main():
    """
    Module entry point.
    """
    arguent_spec = ec2_argument_spec()
    arguent_spec.update(dict(
        vpc_id=dict(required=True),
        vpc_peer_id=dict(required=True),
        state=dict(choices=['present', 'absent'], default='present'),
        wait_timeout=dict(type='int', default=15),
        update_routes=dict(type='bool', default=True)
        ))
    module = AnsibleModule(
        argument_spec=arguent_spec,
    )

    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')

    state = module.params.get('state')
    _, aws_access_key, aws_secret_key, region = get_ec2_creds(module)

    if region:
        try:
            vpc_conn = boto.vpc.connect_to_region(
                region,
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key
            )
        except boto.exception.NoAuthHandlerFound, ex:
            module.fail_json(msg=str(ex))
    else:
        module.fail_json(msg="region must be specified")

    if state == 'present':
        (connection, changed) = create_peer_connection(module, vpc_conn)
        module.exit_json(changed=changed, connection_id=connection)
    elif state == 'absent':
        removed = delete_peer_connection(module, vpc_conn)
        changed = (len(removed) > 0)
        module.exit_json(peering_connections=removed, changed=changed)

from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *
main()