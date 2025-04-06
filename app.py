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

# Configure logging level based on the LOGWEB environment variable
log_level = logging.INFO if os.getenv('LOGWEB', 'false').lower() == 'true' else logging.WARNING
log_level = logging.DEBUG

# Configure Flask logging
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
    """Get the real client IP address using X-Forwarded-For header or request.remote_addr"""
    return request.headers.get('X-Forwarded-For', request.remote_addr)

# Initialize Flask-Limiter specifying custom key_func // RateLimiter
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
    """Query DKIM for specific prefixes."""
    dkim_records = []
    try:
        # Check if the prefix is valid for DKIM lookup
        if prefix in ['google.', 'selector1.', 'selector2.', 'mlwrx.', 'zoho.', 's1.', 's2.', 'dkim.', 'dkim1.', 'google.']:
            # Query DKIM for the specific prefix and domain
            dkim_record = f"{prefix}_domainkey.{item}"
            try:
                dkim_records = [
                    str(r) for r in dns.resolver.resolve(dkim_record, 'TXT', raise_on_no_answer=False)
                ]
                if not dkim_records:
                    return []  # If no records, return an empty list (hide the entry)
            except dns.resolver.NoAnswer:
                return []  # If no answer, return an empty list (hide the entry)
        else:
            return []  # Invalid prefix for DKIM query
    except Exception as e:
        return []  # On any error, return an empty list (hide the entry)
    return dkim_records

def query_dns(item, advanced=False):
    """Query DNS records for the given item."""
    results = {}
    try:
        if is_ip_address(item):
            # PTR lookup for IP
            ptr_record = dns.reversename.from_address(item)
            try:
                ptr_result = str(dns.resolver.resolve(ptr_record, 'PTR')[0])
                results['PTR'] = ptr_result
            except dns.resolver.NoAnswer:
                pass  # Do nothing if no PTR record is found
        else:
            # Perform DNS queries for domain names
            if advanced:
                # Fetch advanced records (MX, DMARC, DKIM)
                try:
                    mx_records = [str(r.exchange) for r in dns.resolver.resolve(item, 'MX')]
                    if mx_records:
                        results['MX'] = mx_records
                except dns.resolver.NoAnswer:
                    pass  # Skip if no MX record found
                
                try:
                    dmarc_records = [
                        str(r) for r in dns.resolver.resolve('_dmarc.' + item, 'TXT', raise_on_no_answer=False)
                    ]
                    if dmarc_records:
                        results['DMARC'] = dmarc_records
                except dns.resolver.NoAnswer:
                    pass  # Skip if no DMARC record found

                # Query DKIM for specified prefixes
                dkim_records = {}
                for prefix in ['google.', 'selector1.', 'selector2.', 'mlwrx.', 'zoho.', 's1.', 's2.', 'dkim.', 'dkim1.', 'google.']:
                    dkim_result = query_dkim_for_prefix(prefix, item)
                    if dkim_result:  # Only add DKIM if records exist
                        dkim_records[prefix] = dkim_result
                if dkim_records:
                    results['DKIM'] = dkim_records

            try:
                # Query for A and AAAA records
                a_records = [str(r) for r in dns.resolver.resolve(item, 'A')]
                if a_records:
                    results['A'] = a_records
            except dns.resolver.NoAnswer:
                pass  # Skip if no A records found

            try:
                aaaa_records = [str(r) for r in dns.resolver.resolve(item, 'AAAA')]
                if aaaa_records:
                    results['AAAA'] = aaaa_records
            except dns.resolver.NoAnswer:
                pass  # Skip if no AAAA records found
                
            try:
                cname_records = [str(r) for r in dns.resolver.resolve(item, 'CNAME')]
                if cname_records:
                    results['CNAME'] = cname_records
            except dns.resolver.NoAnswer:
                pass  # Skip if no CNAME records found        

            try:
                ns_records = [str(r) for r in dns.resolver.resolve(item, 'NS')]
                if ns_records:
                    results['NS'] = ns_records
            except dns.resolver.NoAnswer:
                pass  # Skip if no NS records found         

            try:
                txt_records = [str(r) for r in dns.resolver.resolve(item, 'TXT')]
                if txt_records:
                    results['TXT'] = txt_records
            except dns.resolver.NoAnswer:
                pass  # Skip if no NS records found

            #####WWW
            try:
                # Attempt to resolve CNAME records for 'www.<item>'
                www_records = [str(r) for r in dns.resolver.resolve('www.' + item, 'CNAME')]
                if www_records:
                    results['WWW'] = www_records
            except dns.resolver.NoAnswer:
                # If no CNAME records, attempt to resolve A records
                try:
                    www_records = [str(r) for r in dns.resolver.resolve('www.' + item, 'A')]
                    if www_records:
                        results['WWW'] = www_records
                except dns.resolver.NoAnswer:
                    pass  # Skip if no A records are found            

            #####mail
            try:
                # Attempt to resolve CNAME records for 'mail.<item>'
                mail_records = [str(r) for r in dns.resolver.resolve('mail.' + item, 'CNAME')]
                if mail_records:
                    results['MAIL'] = mail_records
            except dns.resolver.NoAnswer:
                # If no CNAME records, attempt to resolve A records
                try:
                    mail_records = [str(r) for r in dns.resolver.resolve('mail.' + item, 'A')]
                    if mail_records:
                        results['MAIL'] = mail_records
                except dns.resolver.NoAnswer:
                    pass  # Skip if no A records are found              

            #####ftp
            try:
                # Attempt to resolve CNAME records for 'ftp.<item>'
                ftp_records = [str(r) for r in dns.resolver.resolve('ftp.' + item, 'CNAME')]
                if ftp_records:
                    results['FTP'] = ftp_records
            except dns.resolver.NoAnswer:
                # If no CNAME records, attempt to resolve A records
                try:
                    ftp_records = [str(r) for r in dns.resolver.resolve('ftp.' + item, 'A')]
                    if ftp_records:
                        results['FTP'] = ftp_records
                except dns.resolver.NoAnswer:
                    pass  # Skip if no A records are found                         

    except Exception as e:
        results['error'] = str(e)

    return results
    
def sort_dict_values(data):
    """Recursively sort dictionaries and lists by their values."""
    if isinstance(data, dict):
        # Sort the dictionary by its keys
        return {key: sort_dict_values(value) for key, value in sorted(data.items())}
    elif isinstance(data, list):
        # Sort the list
        return sorted(data)
    else:
        return data    
    
# Store DNS query history in Redis
def store_dns_history(item, result):
    """Store DNS query history for a given domain or IP address, only if result changes."""
    history_key = f"dns_history:{item}"
    timestamp = datetime.now().isoformat()

    # Sort the result dictionary by its keys to ensure consistent order
    sorted_result = json.dumps(sort_dict_values(result), sort_keys=True)

    history_entry = {
        "result": sorted_result,  # Store sorted result
        "timestamp": timestamp,
    }

    # Fetch the latest history entry from Redis
    latest_entry = r.lindex(history_key, -1)
    if latest_entry:
        latest_entry = json.loads(latest_entry)
        # Compare results to only store if changed
        if latest_entry["result"] == sorted_result:
            app.logger.info("Src: %s - DNS history update skipped, entries unchanged: %s", item, sorted_result)
            return  # No change, so do not store

    # Append the new entry to the history list in Redis
    r.rpush(history_key, json.dumps(history_entry))

    # Trim the list to keep only the last 50 entries
    r.ltrim(history_key, -50, -1)
    
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def index():
    if request.method == 'POST':
        ips_and_domains = request.form.get("ips_and_domains", "")
        whois_enabled = request.form.get("whois", "off") == "on"  # Check if WHOIS is enabled
        advanced = request.form.get("advanced", "off") == "on"    # Check if DNS is enabled
        items = [item.strip() for item in ips_and_domains.replace(',', '\n').splitlines() if item.strip()]

        client_ip = get_client_ip()
        results = {}
        
        for item in items:
            results[item] = {}  # Initialize an empty dict for each item
            cache_key_whois = f"whois:{item}"
            cache_key_dns = f"dns:{item}"

            # Perform WHOIS query only if enabled
            if whois_enabled:
                cached_data_whois = r.get(cache_key_whois)
                if cached_data_whois:
                    app.logger.info("Src: %s - Cache hit for WHOIS %s", client_ip, item)
                    results[item]["whois"] = cached_data_whois.decode('utf-8')
                else:
                    try:
                        whois_info = whois.whois(item)
                        r.setex(cache_key_whois, timedelta(hours=24), whois_info.text)
                        app.logger.info("Src: %s - WHOIS query successful for: %s", client_ip, item)
                        results[item]["whois"] = whois_info.text
                    except Exception as e:
                        results[item]["whois"] = f"Error: {str(e)}"

            # Perform DNS query only if advanced is enabled
            if advanced:
                cached_data_dns = r.get(cache_key_dns)
                if cached_data_dns:
                    app.logger.info(f"Src: %s - Cache hit for DNS  %s", client_ip, item)
                    try:
                        results[item]["dns"] = eval(cached_data_dns.decode('utf-8'))
                    except Exception as e:
                        app.logger.error(f"Src: %s - Error parsing cached DNS data for %s", client_ip, item)
                        results[item]["dns"] = {"error": "Invalid cached data format."}
                else:
                    try:
                        dns_results = query_dns(item, advanced=True)
                        app.logger.info(f"Src: %s - DNS query results for %s", client_ip, item)
                        r.setex(cache_key_dns, timedelta(minutes=10), str(dns_results))
                        results[item]["dns"] = dns_results
                        store_dns_history(item, dns_results)
                        app.logger.info("Src: %s - Dns history updated, entries changed: %s", client_ip, item)
                    except Exception as e:
                        app.logger.error(f"Src: %s - Error querying DNS for %s", client_ip, item)
                        results[item]["dns"] = {"error": str(e)}

                # Fetch DNS history
                history_key = f"dns_history:{item}"
                history_data = []
                raw_history = r.lrange(history_key, 0, -1)
                raw_history.reverse()
                for entry in raw_history:
                    try:
                        history_data.append(json.loads(entry))
                    except Exception as e:
                        app.logger.error(f"Error parsing DNS history for {item}: {str(e)}")
                results[item]["history"] = history_data
        
        return render_template('index.html', results=results, whois_enabled=whois_enabled, advanced=advanced)

    return render_template('index.html', whois_enabled=False, advanced=False)

@app.route('/query', methods=['GET'])
@app.route('/query/<string:item>', methods=['GET'])
@limiter.limit("5 per minute")
def query_ip(item=None):
    client_ip = get_client_ip()

    if item:
        item = item
    else:
        item = request.args.get('item')
        if not item:
            query_string = request.query_string.decode('utf-8')
            if query_string:
                item = query_string.strip()

    if not item:
        return "Error: No IP address or domain provided. Use /query/<IP_or_Domain> or /query?item=<IP_or_Domain>", 400

    whois_enabled = request.args.get('whois', 'off') == 'on'  # Check if WHOIS is enabled via query param
    advanced = request.args.get('advanced', 'off') == 'on'    # Check if DNS is enabled via query param
    cache_key_whois = f"whois:{item}"
    cache_key_dns = f"dns:{item}"
    results = {item: {}}

    # Perform WHOIS query only if enabled
    if whois_enabled:
        cached_data_whois = r.get(cache_key_whois)
        if cached_data_whois:
            app.logger.info(f"Src: %s - Cache hit for WHOIS : %s", client_ip, item)
            results[item]["whois"] = cached_data_whois.decode('utf-8')
        else:
            try:
                whois_info = whois.whois(item)
                result = whois_info.text
                r.setex(cache_key_whois, timedelta(hours=24), result)
                app.logger.info("Src: %s - WHOIS query successful for: %s", client_ip, item)
                results[item]["whois"] = result
            except Exception as e:
                app.logger.error("Src: %s - Error querying WHOIS for %s: %s", client_ip, item, str(e))
                results[item]["whois"] = f"Error: {str(e)}"

    # Perform DNS query only if advanced is enabled
    if advanced:
        cached_data_dns = r.get(cache_key_dns)
        if cached_data_dns:
            app.logger.info(f"Src: %s - Cache hit for DNS  %s", client_ip, item)
            try:
                results[item]["dns"] = eval(cached_data_dns.decode('utf-8'))
            except Exception as e:
                app.logger.error(f"Src: %s - Error parsing cached DNS data for %s", client_ip, item)
                results[item]["dns"] = {"error": "Invalid cached data format."}
        else:
            try:
                dns_results = query_dns(item, advanced=True)
                app.logger.info(f"Src: %s - DNS query results for %s", client_ip, item)
                r.setex(cache_key_dns, timedelta(minutes=10), str(dns_results))
                results[item]["dns"] = dns_results
                store_dns_history(item, dns_results)
                app.logger.info("Src: %s - Dns history updated, entries changed: %s", client_ip, item)
            except Exception as e:
                app.logger.error(f"Src: %s - Error querying DNS for %s", client_ip, item)
                results[item]["dns"] = {"error": str(e)}

        # Fetch DNS history
        history_key = f"dns_history:{item}"
        history_data = []
        raw_history = r.lrange(history_key, 0, -1)
        raw_history.reverse()
        for entry in raw_history:
            try:
                history_data.append(json.loads(entry))
            except Exception as e:
                app.logger.error(f"Error parsing DNS history for {item}: {str(e)}")
        results[item]["history"] = history_data

    return render_template('index.html', results=results, whois_enabled=whois_enabled, advanced=advanced)

@app.route('/static/<path:filename>')
def static_files(filename):
    response = make_response(send_from_directory('static', filename))
    response.headers['Cache-Control'] = 'public, max-age=10800'  # Cache for 3 hours
    return response

def download_image():
    """Download image from Unsplash and save it to the local directory"""
    try:
        url = 'https://unsplash.it/1920/1080/?grayscale'
        image_content = requests.get(url).content
        image_path = 'static/background.jpg'
        
        with open(image_path, 'wb') as f:
            f.write(image_content)
        
        app.logger.info("Image downloaded successfully: %s", image_path)
    except Exception as e:
        app.logger.error("Error downloading image: %s", str(e))

# Set up a scheduler to download the image once on startup and then every 3 hours
scheduler = BackgroundScheduler()
# Run the job once on startup
scheduler.add_job(download_image, 'date', run_date=datetime.now())
# Run the job every 3 hours after that
scheduler.add_job(download_image, 'interval', hours=3)
scheduler.start()

if __name__ == '__main__':
    download_image()  # Download the image when the app starts
    app.run(host='0.0.0.0', port=5000)
