import whois
import dns.resolver
import dns.reversename
import time
import redis
import os
import socket
import logging
from flask import Flask, request, render_template, send_from_directory, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import json

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

# Configure logging
log_level = logging.INFO if os.getenv('LOGWEB', 'false').lower() == 'true' else logging.WARNING
log_level = logging.DEBUG
app.logger.setLevel(log_level)

app.logger.info(" ____    ____   ")
app.logger.info("|   _\\  |  _ \\  ╔═════════════════════════╗")
app.logger.info("| | | | | |_) | ║    whois                ║")
app.logger.info("| |_| | |  _ <  ║    app                  ║")
app.logger.info("|____/  |_| \\_\\ ╚═════════════════════════╝")
app.logger.info("starting.....")

# Connect to Redis
redis_host = os.getenv('REDIS_HOST', 'redis')
redis_port = int(os.getenv('REDIS_PORT', 6379))
redis_db = int(os.getenv('REDIS_DB', 0))
r = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db)

# Connect to Redis for rate limiter storage
limiter_redis = redis.StrictRedis(host=os.getenv('REDIS_HOST', 'redis'),
                                  port=int(os.getenv('REDIS_PORT', 6379)),
                                  db=int(os.getenv('REDIS_LIM_DB', 1)))

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

# Initialize Flask-Limiter
limiter = Limiter(
    key_func=get_client_ip,
    app=app,
    storage_uri=f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', 6379)}/{os.getenv('REDIS_LIM_DB', 1)}",
    default_limits=["100 per minute"]
)

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

def query_dkim_for_prefix(prefix, item):
    dkim_records = []
    try:
        if prefix in ['google.', 'selector1.', 'selector2.', 'mlwrx.', 'zoho.', 's1.', 's2.', 'dkim.', 'dkim1.', 'google.']:
            dkim_record = f"{prefix}_domainkey.{item}"
            try:
                dkim_records = [str(r) for r in dns.resolver.resolve(dkim_record, 'TXT', raise_on_no_answer=False)]
                if not dkim_records:
                    return []
            except dns.resolver.NoAnswer:
                return []
        else:
            return []
    except Exception:
        return []
    return dkim_records

def fetch_ct_subdomains(domain):
    """Fetch subdomains from crt.sh, ignoring expired certificates, and lookup A/CNAME."""
    try:
        app.logger.info(f"Starting CT lookup for domain: {domain}")
        url = f"https://crt.sh/?q={domain}&output=json"
        app.logger.debug(f"Sending request to: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        app.logger.debug(f"Received {len(data)} entries from crt.sh for {domain}")

        subdomains = {}
        current_date = datetime.now()

        # Supported date formats
        date_formats = [
            "%Y-%m-%dT%H:%M:%SZ",    # e.g., 2025-06-01T12:00:00Z
            "%Y-%m-%dT%H:%M:%S",     # e.g., 2013-06-07T19:43:27
            "%Y-%m-%d",              # e.g., 2025-06-01 (fallback for simpler formats)
        ]

        for entry in data:
            name_value = entry.get('name_value', '').strip()
            not_after = entry.get('not_after', '')
            if not name_value or not not_after:
                app.logger.debug(f"Skipping entry with missing name_value or not_after: {entry}")
                continue

            # Try parsing the date with multiple formats
            expiry_date = None
            for fmt in date_formats:
                try:
                    expiry_date = datetime.strptime(not_after, fmt)
                    break
                except ValueError:
                    continue

            # Handle unparsable dates
            if expiry_date is None:
                app.logger.warning(f"Could not parse not_after date for {name_value}: {not_after}. Including anyway.")
            elif expiry_date < current_date:
                app.logger.debug(f"Skipping expired certificate for {name_value}, expired on {not_after}")
                continue

            # Process subdomains
            for subdomain in name_value.split('\n'):
                subdomain = subdomain.strip()
                if subdomain and subdomain.endswith(domain):
                    if subdomain not in subdomains:
                        subdomains[subdomain] = {'A': [], 'CNAME': []}
                        app.logger.debug(f"New subdomain found: {subdomain}")
                    try:
                        a_records = [str(r) for r in dns.resolver.resolve(subdomain, 'A', raise_on_no_answer=False)]
                        if a_records:
                            subdomains[subdomain]['A'] = a_records
                            app.logger.debug(f"A records for {subdomain}: {a_records}")
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        app.logger.debug(f"No A records for {subdomain}")
                    try:
                        cname_records = [str(r) for r in dns.resolver.resolve(subdomain, 'CNAME', raise_on_no_answer=False)]
                        if cname_records:
                            subdomains[subdomain]['CNAME'] = cname_records
                            app.logger.debug(f"CNAME records for {subdomain}: {cname_records}")
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        app.logger.debug(f"No CNAME records for {subdomain}")

        app.logger.info(f"CT lookup completed for {domain}: {len(subdomains)} subdomains found")
        return subdomains
    except requests.RequestException as e:
        app.logger.error(f"CT lookup failed for {domain}: {str(e)}")
        return {'error': f"Error: {str(e)}"}

def query_dns(item, advanced=False):
    results = {}
    
    # PTR for IPs
    if is_ip_address(item):
        try:
            ptr_record = dns.reversename.from_address(item)
            ptr_result = str(dns.resolver.resolve(ptr_record, 'PTR')[0])
            results['PTR'] = ptr_result
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
            app.logger.debug(f"PTR lookup failed for {item}: {str(e)}")
    
    # Domain lookups
    else:
        # MX Records
        if advanced:
            try:
                mx_records = [str(r.exchange) for r in dns.resolver.resolve(item, 'MX')]
                if mx_records:
                    results['MX'] = mx_records
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
                app.logger.debug(f"MX lookup failed for {item}: {str(e)}")

            # DMARC Records
            try:
                dmarc_records = [str(r) for r in dns.resolver.resolve('_dmarc.' + item, 'TXT', raise_on_no_answer=False)]
                if dmarc_records:
                    results['DMARC'] = dmarc_records
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
                app.logger.debug(f"DMARC lookup failed for {item}: {str(e)}")

            # DKIM Records
            dkim_records = {}
            for prefix in ['google.', 'selector1.', 'selector2.', 'mlwrx.', 'zoho.', 's1.', 's2.', 'dkim.', 'dkim1.', 'google.']:
                try:
                    dkim_result = query_dkim_for_prefix(prefix, item)
                    if dkim_result:
                        dkim_records[prefix] = dkim_result
                except Exception as e:
                    app.logger.debug(f"DKIM lookup failed for {prefix}{item}: {str(e)}")
            if dkim_records:
                results['DKIM'] = dkim_records

        # A Records
        try:
            a_records = [str(r) for r in dns.resolver.resolve(item, 'A')]
            if a_records:
                results['A'] = a_records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
            app.logger.debug(f"A lookup failed for {item}: {str(e)}")

        # AAAA Records
        try:
            aaaa_records = [str(r) for r in dns.resolver.resolve(item, 'AAAA')]
            if aaaa_records:
                results['AAAA'] = aaaa_records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
            app.logger.debug(f"AAAA lookup failed for {item}: {str(e)}")

        # CNAME Records
        try:
            cname_records = [str(r) for r in dns.resolver.resolve(item, 'CNAME')]
            if cname_records:
                results['CNAME'] = cname_records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
            app.logger.debug(f"CNAME lookup failed for {item}: {str(e)}")

        # NS Records
        try:
            ns_records = [str(r) for r in dns.resolver.resolve(item, 'NS')]
            if ns_records:
                results['NS'] = ns_records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
            app.logger.debug(f"NS lookup failed for {item}: {str(e)}")

        # TXT Records
        try:
            txt_records = [str(r) for r in dns.resolver.resolve(item, 'TXT')]
            if txt_records:
                results['TXT'] = txt_records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
            app.logger.debug(f"TXT lookup failed for {item}: {str(e)}")

        # WWW Records
        try:
            www_records = [str(r) for r in dns.resolver.resolve('www.' + item, 'CNAME') or dns.resolver.resolve('www.' + item, 'A')]
            if www_records:
                results['WWW'] = www_records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
            app.logger.debug(f"WWW lookup failed for {item}: {str(e)}")

        # MAIL Records
        try:
            mail_records = [str(r) for r in dns.resolver.resolve('mail.' + item, 'CNAME') or dns.resolver.resolve('mail.' + item, 'A')]
            if mail_records:
                results['MAIL'] = mail_records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
            app.logger.debug(f"MAIL lookup failed for {item}: {str(e)}")

        # FTP Records
        try:
            ftp_records = [str(r) for r in dns.resolver.resolve('ftp.' + item, 'CNAME') or dns.resolver.resolve('ftp.' + item, 'A')]
            if ftp_records:
                results['FTP'] = ftp_records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
            app.logger.debug(f"FTP lookup failed for {item}: {str(e)}")

        # Certificate Transparency
        if advanced:
            ct_key = f"ct:{item}"
            try:
                cached_ct = r.get(ct_key)
                if cached_ct:
                    results['CT'] = json.loads(cached_ct.decode('utf-8'))
                else:
                    ct_results = fetch_ct_subdomains(item)
                    r.setex(ct_key, timedelta(hours=24), json.dumps(ct_results))
                    results['CT'] = ct_results
            except Exception as e:
                app.logger.error(f"CT lookup or caching failed for {item}: {str(e)}")
                results['CT'] = {'error': str(e)}

    return results

def sort_dict_values(data):
    if isinstance(data, dict):
        return {key: sort_dict_values(value) for key, value in sorted(data.items())}
    elif isinstance(data, list):
        return sorted(data)
    else:
        return data

def store_dns_history(item, result):
    history_key = f"dns_history:{item}"
    timestamp = datetime.now().isoformat()
    sorted_result = json.dumps(sort_dict_values(result), sort_keys=True)
    history_entry = {"result": sorted_result, "timestamp": timestamp}
    latest_entry = r.lindex(history_key, -1)
    if latest_entry:
        latest_entry = json.loads(latest_entry)
        if latest_entry["result"] == sorted_result:
            app.logger.info("Src: %s - DNS history update skipped, entries unchanged: %s", item, sorted_result)
            return
    r.rpush(history_key, json.dumps(history_entry))
    r.ltrim(history_key, -50, -1)

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def index():
    if request.method == 'POST':
        ips_and_domains = request.form.get("ips_and_domains", "")
        whois_enabled = request.form.get("whois", "off") == "on"
        advanced = request.form.get("advanced", "off") == "on"
        items = [item.strip() for item in ips_and_domains.replace(',', '\n').splitlines() if item.strip()]
        client_ip = get_client_ip()
        results = {}

        for item in items:
            results[item] = {}
            cache_key_whois = f"whois:{item}"
            cache_key_dns = f"dns:{item}"

            if whois_enabled:
                try:
                    cached_data_whois = r.get(cache_key_whois)
                    if cached_data_whois:
                        app.logger.info("Src: %s - Cache hit for WHOIS %s", client_ip, item)
                        results[item]["whois"] = cached_data_whois.decode('utf-8')
                    else:
                        whois_info = whois.whois(item)
                        r.setex(cache_key_whois, timedelta(hours=24), whois_info.text)
                        app.logger.info("Src: %s - WHOIS query successful for: %s", client_ip, item)
                        results[item]["whois"] = whois_info.text
                except Exception as e:
                    app.logger.error(f"Src: %s - WHOIS query failed for {item}: {str(e)}")
                    results[item]["whois"] = f"Error: {str(e)}"

            if advanced:
                try:
                    cached_data_dns = r.get(cache_key_dns)
                    if cached_data_dns:
                        app.logger.info(f"Src: %s - Cache hit for DNS  %s", client_ip, item)
                        results[item]["dns"] = eval(cached_data_dns.decode('utf-8'))
                    else:
                        dns_results = query_dns(item, advanced=True)
                        app.logger.info(f"Src: %s - DNS query results for %s", client_ip, item)
                        r.setex(cache_key_dns, timedelta(minutes=10), str(dns_results))
                        results[item]["dns"] = dns_results
                        store_dns_history(item, dns_results)
                        app.logger.info("Src: %s - DNS history updated, entries changed: %s", client_ip, item)
                except Exception as e:
                    app.logger.error(f"Src: %s - DNS query failed for {item}: {str(e)}")
                    results[item]["dns"] = {"error": str(e)}

                # History fetching remains unchanged but wrapped for safety
                try:
                    history_key = f"dns_history:{item}"
                    history_data = []
                    raw_history = r.lrange(history_key, 0, -1)
                    raw_history.reverse()
                    for entry in raw_history:
                        history_data.append(json.loads(entry))
                    results[item]["history"] = history_data
                except Exception as e:
                    app.logger.error(f"Error fetching DNS history for {item}: {str(e)}")

        return render_template('index.html', results=results, whois_enabled=whois_enabled, advanced=advanced)

    return render_template('index.html', whois_enabled=False, advanced=False)

def download_image():
    try:
        url = 'https://unsplash.it/1920/1080/?grayscale'
        image_content = requests.get(url).content
        image_path = 'static/background.jpg'
        with open(image_path, 'wb') as f:
            f.write(image_content)
        app.logger.info("Image downloaded successfully: %s", image_path)
    except Exception as e:
        app.logger.error("Error downloading image: %s", str(e))

scheduler = BackgroundScheduler()
scheduler.add_job(download_image, 'date', run_date=datetime.now())
scheduler.add_job(download_image, 'interval', hours=3)
scheduler.start()

if __name__ == '__main__':
    download_image()
    app.run(host='0.0.0.0', port=5000)