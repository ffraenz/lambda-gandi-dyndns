
import json, os, base64
from botocore.vendored import requests

def handle_update(event, context):
    """Update endpoint entrypoint"""

    # Verify auth token
    if not verify_auth(event['headers'].get('Authorization', '')):
        print('Received request with invalid authorization token.')
        return {
            'statusCode': 403,
            'body': json.dumps({ 'success': False })
        }

    # Collect update data
    params = event['queryStringParameters']
    ip4_address = params.get('ip', '')
    ip6_address = params.get('ip6', '')
    domain = params.get('domain', '')
    domain_parts = domain.split('.') if domain else []

    # Check wether this is a valid request
    if (not ip4_address and not ip6_address) or len(domain_parts) < 2:
        print('Received invalid request.')
        return {
            'statusCode': 400,
            'body': json.dumps({ 'success': False })
        }

    # Verify that the requested domain is whitelisted
    if not verify_domain(domain):
        print('The requested domain {} is not whitelisted.'.format(domain))
        return {
            'statusCode': 403,
            'body': json.dumps({ 'success': False })
        }

    # Derive domain base and record name from domain parts
    domain_base = '.'.join(domain_parts[-2:])
    record_name = '.'.join(domain_parts[:-2]) if len(domain_parts) > 2 else '@'

    # Update A (IPv4) and/or AAAA (IPv6) DNS records on base domain
    if ip4_address:
        print('Received request to set {} to {}.'.format(domain, ip4_address))
        update_record(domain_base, 'A', record_name, ip4_address)

    if ip6_address:
        print('Received request to set {} to {}.'.format(domain, ip6_address))
        update_record(domain_base, 'AAAA', record_name, ip6_address)

    # Respond
    return {
        'statusCode': 200,
        'body': json.dumps({ 'success': True })
    }

def verify_auth(authorization):
    """Verifies the given authorization header value"""

    username = os.environ['AUTH_USERNAME']
    password = os.environ['AUTH_PASSWORD']
    token = base64.b64encode('{}:{}'.format(username, password).encode())
    return authorization == 'Basic ' + token.decode()

def verify_domain(domain):
    """Verifies wether the given domain is whitelisted"""

    whitelisted_domains = os.environ['DOMAIN_WHITELIST'].split(',')
    return domain in whitelisted_domains

def update_record(domain, record_type, name, value, ttl = None):
    """Updates the given record"""

    # Default record TTL to environment variable
    ttl = ttl if ttl != None else os.environ['RECORD_TTL']

    response = requests.request(
        'PUT',
        'https://dns.api.gandi.net/api/v5/domains/{}/records/{}/{}'.format(
            domain,
            name,
            record_type
        ),
        data=json.dumps({
            'rrset_ttl': ttl,
            'rrset_values': [value]
        }),
        headers={
            'Content-Type': 'application/json',
            'X-Api-Key': os.environ['GANDI_API_KEY']
        }
    )

    # Log result
    print('Updated record {} {} {}.{} to value {} with status {}'.format(
        record_type, ttl, name, domain, value, response.status_code))

    return response.status_code >= 200 and response.status_code <= 299
