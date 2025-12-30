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
from flask import Flask, request, render_template, send_file, jsonify, flash, redirect, url_for, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from functools import wraps
import requests
import aiohttp
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential
import pandas as pd
import ipinfo
import abuseipdb_wrapper
from flask_htmx import HTMX
import ipaddress
import random
from urllib.parse import urlparse, urljoin
from utils.portscan import scan_ports

# === Flask App ===
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me-in-production')
app.config['CACHE_TYPE'] = 'redis'
app.config['CACHE_REDIS_URL'] = f"redis://{os.getenv('REDIS_HOST', 'redis')}:{os.getenv('REDIS_PORT', 6379)}/2"

cache = Cache(app)
htmx = HTMX(app)
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

# === REAL IP FOR REVERSE PROXY ===
def get_real_ip():
    TRUSTED_PROXIES = {'127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'}
    remote = request.remote_addr
    if remote in TRUSTED_PROXIES:
        xff = request.headers.get('X-Forwarded-For')
        if xff:
            for ip in [ip.strip() for ip in xff.split(',')]:
                if ip not in TRUSTED_PROXIES:
                    return ip
        real_ip = request.headers.get('X-Real-IP')
        if real_ip and real_ip not in TRUSTED_PROXIES:
            return real_ip
    return remote or '127.0.0.1'

#Limiter
limiter = Limiter(key_func=get_real_ip, app=app, storage_uri=f"redis://{os.getenv('REDIS_HOST', 'redis')}:{os.getenv('REDIS_PORT', 6379)}/1")

# === Custom Jinja Filter: is_ip ===
def is_ip_filter(value):
    if not value or not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False

app.jinja_env.filters['is_ip'] = is_ip_filter

# === Helper: is_ip_address (Python) ===
def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except:
        return False

# === Login Required Decorator ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            # Build safe HTTPS next URL
            scheme = 'https'  # Always use HTTPS
            host = request.host
            path = request.full_path if request.full_path != '?' else request.path
            next_url = f"{scheme}://{host}{path}"
            return redirect(url_for('login', next=next_url))
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------------------------
# PORT SCANNER ENDPOINT (HTMX) – uses function from utils/portscan.py
# ----------------------------------------------------------------------
@app.route("/scan", methods=["GET", "POST"])
@login_required
@limiter.limit("20 per minute")
def port_scan():
    # ---- 1. Determine target ------------------------------------------------
    remote_ip = get_real_ip()
    manual_target = request.form.get("target", "").strip()

    if manual_target:
        try:
            ip_obj = ipaddress.ip_address(manual_target)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return '<div class="alert alert-danger">Private/reserved IPs not allowed.</div>'
        except ValueError:
            return '<div class="alert alert-danger">Invalid IP address.</div>'
        target = manual_target
    else:
        target = remote_ip

    # ---- 2. Parse ports ----------------------------------------------------
    raw_ports = request.form.get("ports", "80,443,22,21,25,3389")
    try:
        ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip().isdigit()]
        if not ports:
            raise ValueError
    except ValueError:
        return '<div class="alert alert-danger">Ports must be comma-separated numbers.</div>'

    # ---- 3. Run scan --------------------------------------------------------
    scan_result = scan_ports(target, ports)

    # ---- 4. Return **only the fragment** (no layout) -----------------------
    return render_template(
        "scan_result.html",          # <-- fragment only
        target=target,
        remote_ip=remote_ip,
        result=scan_result,
    )

# ----------------------------------------------------------------------
# SINGLE DNS LOOKUP (HTMX)
# ----------------------------------------------------------------------
@app.route("/dns_lookup", methods=["POST"])
@limiter.limit("30 per minute")
def dns_lookup():
    domain = request.form.get("domain", "").strip()
    record_type = request.form.get("type", "A").strip().upper()
    
    if not domain:
        return '<div class="alert alert-warning">Please enter a domain or IP.</div>'
    
    try:
        query_target = domain
        if record_type == 'PTR' and is_ip_address(domain):
            query_target = dns.reversename.from_address(domain)
            
        answers = dns.resolver.resolve(query_target, record_type)
        results = [str(r).rstrip('.') for r in answers]
        return f'<div class="alert alert-success"><strong>{record_type} records for {domain}:</strong><pre class="mb-0 mt-2"><code>' + "\n".join(results) + '</code></pre></div>'
    except Exception as e:
        return f'<div class="alert alert-danger">Error: {str(e)}</div>'

# ----------------------------------------------------------------------
# MAC LOOKUP (HTMX)
# ----------------------------------------------------------------------
@app.route("/mac_lookup", methods=["POST"])
@limiter.limit("30 per minute")
def mac_lookup():
    mac = request.form.get("mac", "").strip()
    if not mac:
        return '<div class="alert alert-warning">Please enter a MAC address.</div>'
    
    cache_key = f"mac:{mac}"
    cached = cache.get(cache_key)
    if cached:
        return f'<div class="alert alert-success"><strong>MAC Vendor for {mac}:</strong><br>{cached}</div>'
    
    try:
        resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if resp.status_code == 200:
            vendor = resp.text
            cache.set(cache_key, vendor, timeout=86400) # Cache for 1 day
            return f'<div class="alert alert-success"><strong>MAC Vendor for {mac}:</strong><br>{vendor}</div>'
        elif resp.status_code == 404:
            return f'<div class="alert alert-warning">Vendor not found for MAC: {mac}</div>'
        else:
            return f'<div class="alert alert-danger">API Error: {resp.status_code}</div>'
    except Exception as e:
        return f'<div class="alert alert-danger">Error: {str(e)}</div>'

# === Async Session ===
async def get_async_session():
    timeout = aiohttp.ClientTimeout(total=70)
    session = aiohttp.ClientSession(timeout=timeout)
    logger.debug("Created new aiohttp session")
    return session

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
    # Fetch latest entry to check for changes
    last_entry_raw = r.lindex(f"dns_history:{item}", 0)
    new_result_json = json.dumps(dns_result, sort_keys=True)
    
    if last_entry_raw:
        last_entry = json.loads(last_entry_raw)
        if last_entry.get('result') == new_result_json:
            logger.debug(f"No DNS change for {item}, skipping history update.")
            return

    entry = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'result': new_result_json
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
            
            if mech in ['a', 'mx', 'include', 'ptr', 'exists']:
                val['dns_lookups'] += 1
            elif mech == 'redirect':
                val['dns_lookups'] += 1
            
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
    is_ip = is_ip_address(item)
    cache_key = f"query:{item}:{dns_enabled}:{whois_enabled}:{ct_enabled}"
    cached = cache.get(cache_key)
    if cached is not None:
        logger.debug(f"Cache hit for {item}")
        return cached

    result = {'whois': None, 'dns': None, 'ct': None}

    if whois_enabled:
        try:
            w = whois.whois(item)
            result['whois'] = str(w)
        except Exception as e:
            result['whois'] = f"WHOIS error: {str(e)}"

    if dns_enabled:
        dns_result = {}
        if is_ip:
            try:
                rev = dns.reversename.from_address(item)
                ptr_records = dns.resolver.resolve(rev, 'PTR', raise_on_no_answer=False)
                dns_result['PTR'] = [str(r).rstrip('.') for r in ptr_records]
            except Exception as e:
                logger.debug(f"PTR lookup failed for {item}: {e}")
                dns_result['PTR'] = []
        else:
            record_types = ['A', 'AAAA', 'CNAME', 'NS', 'TXT', 'MX']
            dns_result.update(parallel_dns_lookup(item, record_types))

            if 'TXT' in dns_result:
                dns_result['TXT'] = [t.strip('"\'') for t in dns_result['TXT']]
                dns_result['TXT'] = sorted(dns_result['TXT'], key=str.lower)

            spf_records = parse_spf(dns_result.get('TXT', []))
            dns_result['SPF'] = spf_records

            if spf_records:
                validations = [validate_spf_record(rec, item) for rec in spf_records]
                global_errors = ["Multiple SPF records found (RFC 7208 permits only one)"] if len(spf_records) > 1 else []
                dns_result['SPF_validation'] = {
                    'validations': validations,
                    'global_errors': global_errors
                }

            try:
                dmarc = dns.resolver.resolve('_dmarc.' + item, 'TXT', raise_on_no_answer=False)
                dmarc_records = [str(r).strip('"') for r in dmarc if 'v=DMARC1' in str(r)]
                if dmarc_records:
                    dns_result['DMARC'] = dmarc_records
            except Exception as e:
                logger.debug(f"DMARC lookup failed: {e}")

            well_known = query_well_known(item)
            if well_known:
                dns_result['Well-Known'] = well_known

        result['dns'] = dns_result
        store_dns_history(item, dns_result)

    if ct_enabled and not is_ip:
        old_handler = signal.getsignal(signal.SIGALRM)
        try:
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(60)
            ct_result = asyncio.run(fetch_ct_subdomains_async(item))
            result['ct'] = ct_result
            signal.alarm(0)
        except TimeoutError:
            result['ct'] = {'error': 'CT lookup timed out after 60 seconds'}
        except Exception as e:
            result['ct'] = {'error': f"CT failed: {str(e)}"}
        finally:
            signal.signal(signal.SIGALRM, old_handler)
    elif ct_enabled and is_ip:
        result['ct'] = {'error': 'Certificate Transparency not applicable to IP addresses'}

    cache.set(cache_key, result, timeout=600)
    return result

# === EXPORT TO CSV ===
def export_csv(results):
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Domain/IP', 'Type', 'Record', 'Value'])
    
    for item, data in results.items():
        if data.get('whois'):
            lines = data['whois'].strip().split('\n')
            for line in lines:
                if ':' in line:
                    k, v = line.split(':', 1)
                    writer.writerow([item, 'WHOIS', k.strip(), v.strip()])
        
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
            
            if dns.get('SPF_validation'):
                val = dns['SPF_validation']
                for rec in val.get('validations', []):
                    status = "VALID" if rec['valid'] else "INVALID"
                    lookups = rec.get('dns_lookups', 'N/A')
                    writer.writerow([item, 'SPF', f"{status} ({lookups} lookups)", rec['record']])
                
                for err in val.get('global_errors', []):
                    writer.writerow([item, 'SPF_ERROR', '', err])
            
            if dns.get('Well-Known'):
                for fqdn, recs in dns['Well-Known'].items():
                    for rtype, values in recs.items():
                        for val in values:
                            writer.writerow([item, 'WELL_KNOWN', f"{fqdn} {rtype}", val])
        
        if data.get('ct') and 'error' not in data['ct']:
            for sub in data['ct'].keys():
                writer.writerow([item, 'CT', 'SUBDOMAIN', sub])
    
    return output.getvalue()

# === Monitoring System ===
MONITORED_KEY = "monitored_items"

def monitor_item(item):
    logger.info(f"[MONITOR] Running scheduled check for {item}")
    result = query_item(item, dns_enabled=True, whois_enabled=True, ct_enabled=not is_ip_address(item))
    logger.debug(f"[MONITOR] Result: {json.dumps(result)[:500]}...")

def schedule_monitoring_jobs():
    scheduler.remove_all_jobs()
    items = r.lrange(MONITORED_KEY, 0, -1)
    items = [item.decode('utf-8') for item in items]
    if not items:
        logger.info("No monitored items.")
        return

    total_minutes = 23 * 60  # 23-hour window
    interval = total_minutes / len(items)
    for idx, item in enumerate(items):
        delay = int(idx * interval + random.uniform(0, 30))
        hour = delay // 60
        minute = delay % 60
        trigger = CronTrigger(hour=hour, minute=minute)
        scheduler.add_job(
            func=lambda i=item: monitor_item(i),
            trigger=trigger,
            id=f"monitor_{item}",
            name=f"Monitor {item}",
            replace_existing=True
        )
        logger.info(f"Scheduled {item} → {hour:02d}:{minute:02d}")

# === Routes ===
@app.route('/', methods=['GET', 'POST'])
def index():
    real_ip = get_real_ip()  # Compute the real IP here
    
    if request.method == 'POST':
        ips_and_domains = request.form.get('ips_and_domains', '').strip()
        export_type = request.form.get('export')
        whois_enabled = 'whois' in request.form
        dns_enabled = 'dns' in request.form
        ct_enabled = 'ct' in request.form
        
        items = [i.strip() for i in ips_and_domains.split(',') if i.strip()]
        ordered_items = items[:]  # Preserve order
        
        results = {}
        has_ip = any(is_ip_address(i) for i in items)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_item = {executor.submit(query_item, item, dns_enabled, whois_enabled, ct_enabled): item for item in items}
            for future in as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    results[item] = future.result()
                except Exception as e:
                    results[item] = {'error': str(e)}
        
        if export_type == 'csv':
            si = StringIO()
            cw = csv.writer(si)
            cw.writerow(['Item', 'Type', 'Data'])
            for item, data in results.items():
                for key, val in data.items():
                    cw.writerow([item, key, json.dumps(val)])
            si.seek(0)
            return send_file(BytesIO(si.getvalue().encode('utf-8')), mimetype='text/csv', download_name='results.csv')
        
        return render_template(
            'index.html',
            results=results,
            ordered_items=ordered_items,
            whois_enabled=whois_enabled,
            dns_enabled=dns_enabled,
            ct_enabled=ct_enabled,
            has_ip=has_ip,
            auto_expand=True,
            real_ip=real_ip  # Pass the computed real IP to the template
        )
    
    return render_template('index.html', auto_expand=False, real_ip=real_ip)  # Also pass it for GET requests
    
@app.route('/ip')
def show_ip():
    return jsonify({
            'remote_addr': request.remote_addr,
            'xff': request.headers.get('X-Forwarded-For'),
            'x_real_ip': request.headers.get('X-Real-IP'),
            'host': request.host,
            'user_agent': request.headers.get('User-Agent'),
            'real_ip': get_real_ip()
        })

@app.route('/login', methods=['GET', 'POST'])
def login():
    raw_next = request.args.get('next')
    default_next = url_for('config', _external=True, _scheme='https')

    # Sanitize next URL
    if raw_next:
        parsed = urlparse(raw_next)
        if parsed.scheme == 'https' and parsed.netloc == request.host:
            safe_next = raw_next
        else:
            safe_next = default_next
    else:
        safe_next = default_next

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        env_user = os.getenv('CONFIG_USER')
        env_pass = os.getenv('CONFIG_PASS')

        if env_user and env_pass and username == env_user and password == env_pass:
            session['logged_in'] = True
            return redirect(safe_next)
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html', next=safe_next)

@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/config', methods=['GET', 'POST'])
@login_required
@limiter.exempt
def config():
    if request.method == 'POST':
        action = request.form.get('action')
        item = request.form.get('item', '').strip().lower()

        if action == 'add' and item:
            if (is_ip_address(item) or '.' in item) and item not in [i.decode() for i in r.lrange(MONITORED_KEY, 0, -1)]:
                r.rpush(MONITORED_KEY, item)
                flash(f"Added {item} to monitoring", "success")
                schedule_monitoring_jobs()
            else:
                flash("Invalid or duplicate item", "danger")
        elif action == 'remove' and item:
            r.lrem(MONITORED_KEY, 0, item)
            try:
                scheduler.remove_job(f"monitor_{item}")
            except:
                pass
            flash(f"Removed {item}", "success")
            schedule_monitoring_jobs()
        return redirect(url_for('config'))

    monitored = [i.decode() for i in r.lrange(MONITORED_KEY, 0, -1)]
    jobs = [
        {
            'id': j.id,
            'name': j.name.split(' ', 1)[1] if ' ' in j.name else j.id,
            'next_run': j.next_run_time.strftime('%Y-%m-%d %H:%M') if j.next_run_time else '—'
        }
        for j in scheduler.get_jobs()
        if j.id.startswith('monitor_')
    ]
    return render_template('config.html', monitored=monitored, jobs=jobs)

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
        diff_lines = list(unified_diff(previous_lines, current_lines, lineterm=''))
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

# === Start Scheduler & Monitoring ===
scheduler.start()
scheduler.add_job(schedule_monitoring_jobs, 'interval', minutes=5, id='refresh_monitoring')
schedule_monitoring_jobs()

# === Run ===
if __name__ == '__main__':
    download_background()
    app.run(host='0.0.0.0', port=5000, debug=False)