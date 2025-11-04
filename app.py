import whois
import dns.resolver
import dns.reversename
import time
import redis
import os
import socket
import logging
import json
import csv
import signal
from io import StringIO, BytesIO
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, render_template, send_file, jsonify, flash, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import aiohttp
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential
import pandas as pd
import ipinfo
import abuseipdb_wrapper
from flask_htmx import HTMX

# === Flask App ===
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey')
app.config['CACHE_TYPE'] = 'redis'
app.config['CACHE_REDIS_URL'] = f"redis://{os.getenv('REDIS_HOST', 'redis')}:{os.getenv('REDIS_PORT', 6379)}/2"

cache = Cache(app)
htmx = HTMX(app)
limiter = Limiter(key_func=get_remote_address, app=app, storage_uri=f"redis://{os.getenv('REDIS_HOST', 'redis')}:{os.getenv('REDIS_PORT', 6379)}/1")
r = redis.StrictRedis(host=os.getenv('REDIS_HOST', 'redis'), port=int(os.getenv('REDIS_PORT', 6379)), db=0)

# === Logging ===
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('whois-app')
logger.debug("Application starting...")

app.logger.info(" ____    ____   ")
app.logger.info("|   _\\  |  _ \\  ╔═════════════════════════╗")
app.logger.info("| | | | | |_) | ║    whois                ║")
app.logger.info("| |_| | |  _ <  ║    app                  ║")
app.logger.info("|____/  |_| \\_\\ ╚═════════════════════════╝")
app.logger.info("starting.....")

# === Async Session ===
async def get_async_session():
    timeout = aiohttp.ClientTimeout(total=70)
    session = aiohttp.ClientSession(timeout=timeout)
    logger.debug("Created new aiohttp session")
    return session

# === Helper: IP Check ===
def is_ip_address(value):
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except socket.error:
            return False

# === Parallel DNS Lookup ===
def parallel_dns_lookup(domain, record_types):
    logger.debug(f"Starting parallel DNS lookup for {domain}: {record_types}")
    results = {}
    def lookup(rt):
        try:
            answers = dns.resolver.resolve(domain, rt, raise_on_no_answer=False)
            recs = [str(r) for r in answers]
            logger.debug(f"DNS {rt} for {domain}: {recs}")
            return rt, recs
        except Exception as e:
            logger.debug(f"DNS {rt} failed for {domain}: {e}")
            return rt, []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(lookup, rt): rt for rt in record_types}
        for future in as_completed(futures):
            rt, recs = future.result()
            if recs:
                results[rt] = recs
    logger.debug(f"Parallel DNS complete for {domain}: {list(results.keys())}")
    return results

# === Well-known subdomains ===
def query_well_known(domain):
    well_known = {}
    subs = [
        'www', 'mail', 'ftp', 'webmail', 'admin', 'cpanel', 'login', 'secure',
        'smtp', 'pop', 'imap', 'autodiscover', 'autoconfig', 'mta-sts',
        'vpn', 'remote', 'gateway', 'portal', 'cloud', 'api', 'dev', 'test',
        'staging', 'beta', 'demo', 'status', 'monitor', 'metrics', 'health',
        'shop', 'store', 'blog', 'forum', 'wiki', 'docs', 'support', 'help',
        'cdn', 'static', 'assets', 'media', 'images', 'files', 'download'
    ]
    record_types = ['A', 'AAAA', 'CNAME']
    
    for sub in subs:
        fqdn = f"{sub}.{domain}"
        try:
            result = parallel_dns_lookup(fqdn, record_types)
            if result:
                well_known[fqdn] = result
                logger.debug(f"Well-known {fqdn}: {result}")
        except Exception as e:
            logger.debug(f"Well-known {fqdn} failed: {e}")
    
    return well_known

# === CT Subdomains ===
async def fetch_ct_subdomains_async(domain):
    cache_key = f"ct:{domain}"
    cached = cache.get(cache_key)
    if cached is not None:
        logger.debug(f"CT cache hit for {domain}")
        return cached

    logger.debug(f"Fetching CT logs for {domain}")
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        session = await get_async_session()
        logger.debug(f"GET {url}")
        async with session.get(url, timeout=60) as resp:
            if resp.status != 200:
                raise Exception(f"HTTP {resp.status}: {resp.reason}")
            text = await resp.text()
            if not text.strip():
                raise Exception("Empty response from crt.sh")
            logger.debug(f"CT response size: {len(text)} bytes")
            data = json.loads(text)
    except asyncio.TimeoutError:
        error_msg = "CT request timed out after 60 seconds"
        logger.error(error_msg)
        result = {'error': error_msg}
        cache.set(cache_key, result, timeout=3600)
        return result
    except json.JSONDecodeError as e:
        error_msg = f"Invalid JSON from crt.sh: {str(e)}"
        logger.error(error_msg)
        result = {'error': error_msg}
        cache.set(cache_key, result, timeout=3600)
        return result
    except Exception as e:
        error_msg = f"CT request failed: {str(e)}"
        logger.error(error_msg)
        result = {'error': error_msg}
        cache.set(cache_key, result, timeout=3600)
        return result

    subdomains = {}
    for entry in data:
        name = entry.get('name_value', '').strip()
        if not name:
            continue
        for sub in name.split('\n'):
            sub = sub.strip().lstrip('*')
            if sub and sub != domain and sub.endswith('.' + domain):
                subdomains[sub] = subdomains.get(sub, {})
    result = subdomains or {'error': 'No subdomains found in CT logs'}
    cache.set(cache_key, result, timeout=3600)
    return result

# === Timeout handler ===
def timeout_handler(signum, frame):
    raise TimeoutError("CT lookup timed out")

# === Store DNS history ===
def store_dns_history(item, dns_result):
    entry = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'result': json.dumps(dns_result, sort_keys=True)
    }
    r.lpush(f"dns_history:{item}", json.dumps(entry))
    r.ltrim(f"dns_history:{item}", 0, 99)

# === Parse SPF from TXT records ===
def parse_spf(txt_records):
    spf = []
    for txt in txt_records:
        clean = txt.strip('"\'')
        if clean.lower().startswith('v=spf1'):
            clean = ' '.join(clean.split())
            spf.append(clean)
    spf = sorted(spf, key=str.lower)
    logger.debug(f"SPF records found ({len(spf)}): {spf}")
    return spf or None

# === MANUAL SPF VALIDATION ===
def validate_spf_record(record, domain):
    val = {'record': record, 'valid': True, 'warnings': [], 'dns_lookups': 0}
    
    try:
        tokens = record.split()
        if not tokens or tokens[0].lower() != 'v=spf1':
            raise ValueError("Missing or invalid v=spf1")
        
        i = 1
        while i < len(tokens):
            token = tokens[i]
            if ':' in token:
                mech, target = token.split(':', 1)
            elif '=' in token:
                mech, target = token.split('=', 1)
            else:
                mech, target = token, None
            
            mech = mech.lower()
            
            # Count DNS lookups
            if mech in ['a', 'mx', 'include', 'ptr', 'exists']:
                val['dns_lookups'] += 1
            elif mech == 'redirect':
                val['dns_lookups'] += 1
            
            # Validate mechanism
            if mech not in ['+a', '-a', '~a', '?a', 'a',
                           '+mx', '-mx', '~mx', '?mx', 'mx',
                           '+ip4', '-ip4', '~ip4', '?ip4', 'ip4',
                           '+ip6', '-ip6', '~ip6', '?ip6', 'ip6',
                           '+include', '-include', '~include', '?include', 'include',
                           '+ptr', '-ptr', '~ptr', '?ptr', 'ptr',
                           '+exists', '-exists', '~exists', '?exists', 'exists',
                           '+all', '-all', '~all', '?all', 'all',
                           'redirect']:
                val['valid'] = False
                val['warnings'].append(f"Unknown mechanism: {mech}")
            
            i += 1
        
        if val['dns_lookups'] > 10:
            val['valid'] = False
            val['warnings'].append(f"Too many DNS lookups ({val['dns_lookups']} > 10)")
    
    except Exception as e:
        val['valid'] = False
        val['errors'] = [f"Parse error: {str(e)}"]
        val['dns_lookups'] = None
        val['warnings'] = []
    
    return val

# === Query single item ===
def query_item(item, dns_enabled=True, whois_enabled=True, ct_enabled=True):
    cache_key = f"query:{item}:{dns_enabled}:{whois_enabled}:{ct_enabled}"
    cached = cache.get(cache_key)
    if cached is not None:
        logger.debug(f"Cache hit for {item}")
        return cached

    result = {'whois': None, 'dns': None, 'ct': None}

    # WHOIS
    if whois_enabled and not is_ip_address(item):
        try:
            w = whois.whois(item)
            result['whois'] = str(w)
        except Exception as e:
            result['whois'] = f"WHOIS error: {str(e)}"

    # DNS
    if dns_enabled:
        dns_result = {}
        if is_ip_address(item):
            try:
                rev = dns.reversename.from_address(item)
                ptr = str(dns.resolver.resolve(rev, 'PTR')[0]).rstrip('.')
                dns_result['PTR'] = [ptr]
            except Exception as e:
                logger.debug(f"PTR lookup failed for {item}: {e}")
        else:
            record_types = ['A', 'AAAA', 'CNAME', 'NS', 'TXT', 'MX']
            dns_result.update(parallel_dns_lookup(item, record_types))

            # Clean and sort TXT
            if 'TXT' in dns_result:
                dns_result['TXT'] = [t.strip('"\'') for t in dns_result['TXT']]
                dns_result['TXT'] = sorted(dns_result['TXT'], key=str.lower)

            # SPF
            dns_result['SPF'] = parse_spf(dns_result.get('TXT', []))

            # MANUAL SPF VALIDATION
            if dns_result.get('SPF'):
                validations = []
                global_errors = []

                for spf_record in dns_result['SPF']:
                    val = validate_spf_record(spf_record, item)
                    validations.append(val)

                if len(dns_result['SPF']) > 1:
                    global_errors.append("Multiple SPF records found (RFC 7208 permits only one)")

                dns_result['SPF_validation'] = {
                    'validations': validations,
                    'global_errors': global_errors
                }
                logger.debug(f"SPF validation complete for {item}: {len(validations)} record(s)")

            # DMARC
            try:
                dmarc = [str(r) for r in dns.resolver.resolve('_dmarc.' + item, 'TXT', raise_on_no_answer=False)]
                dns_result['DMARC'] = dmarc
            except Exception as e:
                logger.debug(f"DMARC failed: {e}")

            # Well-known
            well_known = query_well_known(item)
            if well_known:
                dns_result['Well-Known'] = well_known

        result['dns'] = dns_result
        store_dns_history(item, dns_result)

    # CT
    if ct_enabled:
        old_handler = signal.getsignal(signal.SIGALRM)
        try:
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(60)
            ct_result = asyncio.run(fetch_ct_subdomains_async(item))
            result['ct'] = ct_result
            signal.alarm(0)
        except TimeoutError:
            logger.warning(f"CT lookup timed out for {item}")
            result['ct'] = {'error': 'CT lookup timed out after 60 seconds'}
        except Exception as e:
            logger.error(f"CT lookup failed for {item}: {e}")
            result['ct'] = {'error': f"CT failed: {str(e)}"}
        finally:
            signal.signal(signal.SIGALRM, old_handler)

    cache.set(cache_key, result, timeout=600)
    logger.debug(f"Query complete for {item}")
    return result
    
# === EXPORT TO CSV ===
def export_csv(results):
    output = StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        'Domain/IP', 'Type', 'Record', 'Value'
    ])
    
    for item, data in results.items():
        # WHOIS
        if data.get('whois'):
            lines = data['whois'].strip().split('\n')
            for line in lines:
                if ':' in line:
                    k, v = line.split(':', 1)
                    writer.writerow([item, 'WHOIS', k.strip(), v.strip()])
        
        # DNS
        if data.get('dns'):
            dns = data['dns']
            for rtype, values in dns.items():
                if rtype in ['SPF_validation', 'Well-Known']:
                    continue
                if isinstance(values, list):
                    for val in values:
                        writer.writerow([item, 'DNS', rtype, val])
                else:
                    writer.writerow([item, 'DNS', rtype, values])
            
            # SPF Validation
            if dns.get('SPF_validation'):
                val = dns['SPF_validation']
                for rec in val.get('validations', []):
                    status = "VALID" if rec['valid'] else "INVALID"
                    lookups = rec.get('dns_lookups', 'N/A')
                    writer.writerow([item, 'SPF', f"{status} ({lookups} lookups)", rec['record']])
                
                for err in val.get('global_errors', []):
                    writer.writerow([item, 'SPF_ERROR', '', err])
            
            # Well-Known
            if dns.get('Well-Known'):
                for fqdn, recs in dns['Well-Known'].items():
                    for rtype, values in recs.items():
                        for val in values:
                            writer.writerow([item, 'WELL_KNOWN', f"{fqdn} {rtype}", val])
        
        # CT
        if data.get('ct') and 'error' not in data['ct']:
            for sub in data['ct'].keys():
                writer.writerow([item, 'CT', 'SUBDOMAIN', sub])
    
    return output.getvalue()

# === Routes ===
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("15 per minute")
def index():
    if request.method == 'POST':
        raw_input = request.form.get("ips_and_domains", "")
        items = [i.strip() for i in raw_input.replace(',', '\n').splitlines() if i.strip()]
        whois_enabled = 'whois' in request.form
        dns_enabled = 'dns' in request.form
        ct_enabled = 'ct' in request.form
        export_type = request.form.get('export')

        logger.info(f"POST query | Items: {len(items)} | WHOIS: {whois_enabled} | DNS: {dns_enabled} | CT: {ct_enabled}")

        results = {}
        ordered_items = []
        for item in items:
            results[item] = query_item(item, dns_enabled=dns_enabled, whois_enabled=whois_enabled, ct_enabled=ct_enabled)
            ordered_items.append(item)

        if export_type == 'csv':
            csv_data = export_csv(results)
            return send_file(
                BytesIO(csv_data.encode()),
                mimetype='text/csv',
                as_attachment=True,
                download_name='results.csv'
            )

        return render_template(
            'index.html',
            results=results,
            ordered_items=ordered_items,
            whois_enabled=whois_enabled,
            dns_enabled=dns_enabled,
            ct_enabled=ct_enabled,
            auto_expand=True
        )

    return render_template('index.html', auto_expand=False)

# === History Route ===
@app.route('/history/<item>')
def history(item):
    raw = r.lrange(f"dns_history:{item}", 0, -1)
    entries = [json.loads(h) for h in raw]
    
    if not entries:
        return jsonify({'entries': [], 'diffs': []})

    entries = sorted(entries, key=lambda x: x['timestamp'], reverse=True)
    diffs = []
    from difflib import unified_diff

    for i in range(len(entries) - 1):
        current = json.loads(entries[i]['result'])
        previous = json.loads(entries[i + 1]['result'])
        current_lines = json.dumps(current, indent=2, sort_keys=True).splitlines()
        previous_lines = json.dumps(previous, indent=2, sort_keys=True).splitlines()

        diff_lines = list(unified_diff(
            previous_lines, current_lines,
            fromfile=f"Older ({entries[i+1]['timestamp'][:10]})",
            tofile=f"Newer ({entries[i]['timestamp'][:10]})",
            lineterm=''
        ))

        diffs.append({
            'from': entries[i+1]['timestamp'],
            'to': entries[i]['timestamp'],
            'diff': '\n'.join(diff_lines) if diff_lines else 'No changes'
        })

    return jsonify({'entries': entries, 'diffs': diffs})

@app.route('/api/query')
@limiter.limit("20 per minute")
def api_query():
    domain = request.args.get('q')
    dns_q = request.args.get('dns', 'false') == 'true'
    whois_q = request.args.get('whois', 'false') == 'true'
    ct_q = request.args.get('ct', 'false') == 'true'
    if not domain:
        return jsonify({'error': 'q parameter required'}), 400
    result = query_item(domain, dns_enabled=dns_q, whois_enabled=whois_q, ct_enabled=ct_q)
    return jsonify(result)

# === Background Image ===
def download_background():
    try:
        img = requests.get('https://picsum.photos/1920/1080?grayscale', timeout=10).content
        with open('static/background.jpg', 'wb') as f:
            f.write(img)
        logger.info("Background image updated")
    except Exception as e:
        logger.warning(f"Background download failed: {e}")

scheduler = BackgroundScheduler()
download_background()
scheduler.add_job(download_background, 'interval', hours=6)
scheduler.start()

# === Run ===
if __name__ == '__main__':
    download_background()
    app.run(host='0.0.0.0', port=5000, debug=False)