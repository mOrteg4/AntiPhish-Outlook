import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
import re
import tldextract
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
import statistics as stats
import socket
from urllib.parse import urlparse

def is_safe_url(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            return False

        ip_address = socket.gethostbyname(hostname)

        # Check if the IP address is in a private range
        if ip_address.startswith('10.') or \
           ip_address.startswith('172.') or \
           ip_address.startswith('192.168.') or \
           ip_address == '127.0.0.1':
            return False

        return True
    except (socket.gaierror, ValueError):
        return False

def preprocess_email_content(email_content):
    print("Preprocessing email contents...")
    extracted = email_content['email_contents']
    preprocessed_content = extracted.lower()
    return preprocessed_content

def transform_email_to_features(preprocessed_content):
    # Initialize a list to store the extracted features
    email_features = []
    multiple_links = []

    # check if there are links
    # has_link = re.findall(r'\<.*?\>', preprocess_email_content)
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    has_link = None
    match = re.search(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', preprocessed_content)
    if match:
        has_link = match.group(0)
    else:
        has_link = None
    has_link_group_type = url_pattern.findall(preprocessed_content)

    #if there are links, get data to check if phishing (im assuming theres one link for now)
    if match and (len(has_link_group_type) != 0):
        #check each website for sub-categories (ex: id, subdomain, etc.)
        for i in range(0, len(has_link_group_type)):
            #expecting multiple links in the email
            if len(email_features) != 0:
                multiple_links.append(email_features)
            email_features.clear()
            
            # GET request to URL
            if not is_safe_url(has_link_group_type[i]):
                print(f"Skipping unsafe URL: {has_link_group_type[i]}")
                continue
            try:
                response = requests.get(has_link_group_type[i], timeout=5)
                response.raise_for_status()  # Raise an exception for bad status codes
            except requests.exceptions.RequestException as e:
                print(f"Error fetching URL {has_link_group_type[i]}: {e}")
                continue

            # parsse HTML content
            temp = BeautifulSoup(response.content, 'html.parser')
            html_content = response.text

            

            """
            URL contains 10 parts, which are what we are looking at
            EXAMPLE: https://www.hello.this.is.an.example.link.com/home/parts-url?/134/
            hostname = www.hello.this.is.an.example.link.com
            scheme = https://
            subdomains = www, hello, this, is, an, example
            domain: link.com
            second-level domain: link
            top-level domain: .com (other examples, .edu, .org, and .net)
            subdictionary: home
            path: parts-url, 
            query: question mark symbol ?, before a query is the path & after are parameters
            ampersand: & symbol, found btw each parameter
            id = 134, random number that the website generated for the link
            """

            # Extract ID
            try:
                id = re.findall('/(\d+)\/|ID=(\d+/g)',has_link_group_type[i])[0]
             # id doesnt-'t exist    
            except:
                id = 0
            email_features.append(int(id))
            
            # Extract NumDots from preprocessed_email_content
            num_dots = has_link_group_type[i].count(".")
            # Handle invalid dots at end of domain name extension    
            ext = tldextract.extract(has_link_group_type[i]) #extracting
            extension = ext.suffix
            if extension and extension[-1] == '.': #checks if the last character in the array is '.' as in careers.csulb.edu. where an invalid '.' is appended to the end of the URL
             num_dots -= 1 #subtracts that from the total
            email_features.append(num_dots) 

            # Extract SubdomainLevel, number is btw 0 - 126
            ext = tldextract.extract(has_link_group_type[i]) #https://pypi.org/project/tldextract/
            subdomain = ext.subdomain
            #remove port
            if ":" in subdomain:
                    subdomain = subdomain.split(":")[0]
            sub_parts = subdomain.split(".")
            if not subdomain:
                sub_parts = []
            if len(sub_parts) < 1:
                sublvl = 0
            else:
                sublvl = len(sub_parts)
            email_features.append(sublvl)

            # Extract PathLevel
            path_segments = has_link_group_type[i].split('/')
            path_level = len([segment for segment in path_segments if segment])  # Count non-empty segments
            email_features.append(path_level)

            # Extract UrlLength
            email_features.append(len(has_link_group_type[i]))

            # Extract NumDash
            num_dash = has_link_group_type[i].count("-")
            email_features.append(num_dash)

            # Extract NumDashInHostname
            hostname = re.findall(r'https?://([^/]+)', has_link_group_type[i])[0]
            num_dash_in_domain = hostname.count("-")
            email_features.append(num_dash_in_domain)
            
            # Extract AtSymbol
            if "@" in has_link_group_type[i]:
                result = 1
            else:
                result = 0
            email_features.append(result)
            
            # Extract TildeSymbol
            if "~" in has_link_group_type[i]:
                result = 1
            else:
                result = 0
            email_features.append(result)

            # Extract NumUnderscore
            num_underscore = has_link_group_type[i].count("_")
            email_features.append(num_underscore)

            # Extract NumPercent from preprocessed_email_content
            num_percent = has_link_group_type[i].count("%")
            email_features.append(num_percent)

            # Queries are after "?" and separated by "&" or "+" until the end of string
            # A Queries starts with a key, has '=' as a seperater, and the values after it
            # r"(\w+)=(\w+)"
            # (\w+) finds all sequences of one or more char (this is the key, usually it is 'q' but it can be a word like 'query')
            # followed by '=' 
            # followed by (\w+) which are more characters (these are the values of the query)
            # example of query of 2 components: https://example.com/page?parameter1=x&parameter2=y
            # queries are parameter1=x and parameter2=y, it would look like this [(parameter1,x), (parameter2=y)]
            # Extract NumQueryComponents
            queries = re.findall(r"(\w+)=(\w+)", has_link_group_type[i])
            query_length = len(queries)
            email_features.append(query_length)

            # Extract NumAmpersand
            num_ampersand = has_link_group_type[i].count("&")
            email_features.append(num_ampersand)

            # Extract NumHash
            num_hash = has_link_group_type[i].count("#")
            email_features.append(num_hash)

            # Extract NumNumericChars
            num_numeric_chars = sum(c.isdigit() for c in has_link_group_type[i])
            email_features.append(num_numeric_chars)

            # Extract NoHttps
            match = re.search(r"^https", has_link_group_type[i])
            if match:
                result = 1
            else:
                result = 0
            email_features.append(result)

            # Extract RandomString
            # find if there is a random string in the link
            # Note: "Random strings in links: creating unique identifiers, preventing caching, or adding security."
            # [a-zA-Z0-9] any sequence of lowercase, lower can uppercase, letters and numbers, and numbers
            # {8,} = any sequence of at least 8
            # matches returns a list of random strings that are found in the link
            matches = re.findall(r"[a-zA-Z0-9]{6,}", has_link_group_type[i], re.IGNORECASE)
            #if there is a random string
            if len(matches) > 0:
                #return true
                result = 1
            else:
                #if there is none, return false
                result = 0
            email_features.append(result)

            # Extract IpAddress
            # Define the regular expression
            regex = r"^ (http|https)://\d+\.\d+\.\d+\.\d+\.*"
            # Compile the regular expression
            pattern = re.compile(regex)
            # Test if the URL matches the regular expression
            if pattern.match(has_link_group_type[i]):
                # Return 0 if true
                ip_address =  0
            else:
                # Return 1 if false
                ip_address = 1
            email_features.append(ip_address)

            # Extract DomainInSubdomains
            parsed_url = urlparse(has_link_group_type[i])
            domain = tldextract.extract(parsed_url.netloc).domain
            result = 0
            for check in range(len(sub_parts)):
                if domain == sub_parts[check]:
                    result = 1
                else:
                    result = 0
            email_features.append(result)

            # Extract DomainInPaths
            parsed_url = urlparse(has_link_group_type[i])
            domain = tldextract.extract(parsed_url.netloc).domain
            paths = parsed_url.path
            # default is domain is not found in path
            result = 0
            # check through each path
            for path in paths.split("/"):
                if domain in path:
                    result = 1
            email_features.append(result)

            # Extract HttpsInHostname
            parsed_url = urlparse(has_link_group_type[i])
            if parsed_url and parsed_url.hostname:
                hostname = parsed_url.hostname
                if "https" in hostname.lower() and not hostname.startswith("https"):
                    result = 1
                else:
                    result = 0
            else:
                result = 0
            email_features.append(result)

            # Extract HostnameLength
            parsed_url = urlparse(has_link_group_type[i])
            if parsed_url.hostname:
                hostname = parsed_url.hostname
                hostname_length = len(hostname)
                email_features.append(hostname_length)
            else:
                email_features.append(0)

            # Extract PathLength
            # max url length is usually under 2000, bc not all browsers can work over it
            # this means anything over is suspisious.
            #r"(?<=/)[^?#]*" finds sequences that does not contain ? or #, and is preceded by a /
            path_length = len(re.findall(r"(?<=/)[^?#]*", has_link_group_type[i]))
            email_features.append(path_length)

            # Extract QueryLength
            # using the same example: https://example.com/page?parameter1=x&parameter2=y
            # urlparse(has_link_group_type[0]).query returns "parameter1=x&parameter2=y"
            # so we use len to get the length of that query string
            parsed_url = urlparse(has_link_group_type[i])
            query_length = len(parsed_url.query)
            email_features.append(query_length)
            
            # Extract DoubleSlashInPath
            #if there are double slashes in the the path, return 1
            parsed_url = urlparse(has_link_group_type[i])
            if re.search("//", parsed_url.path):
                result = 1
            #else there are not then return 0
            else:
                result = 0
            email_features.append(result)
            
            # Extract NumSensitiveWords
            # list of sensitive words
            sensitive_words = ["secure", "account", "webscr", "login", "ebayisapi", "signin", "banking", "confirm"]
            # sum of amount of sensitive words
            num_sensitive_words = sum([1 for word in sensitive_words if re.search(word, has_link_group_type[i], re.IGNORECASE)])
            email_features.append(num_sensitive_words)

            # Extract EmbeddedBrandName
            parsed_url = urlparse(has_link_group_type[i])
            if parsed_url.hostname is not None:
                subdomains = parsed_url.hostname.split(".")[:-2]  # Exclude TLD and domain
                path = parsed_url.path
                # Assuming `temp` contains the HTML content of the webpage
                # Extract domain names from links in the HTML content
                domain_names = [urlparse(link.get("href")).hostname for link in temp.find_all("a") if link.get("href") and urlparse(link.get("href")).hostname]
                # Count the occurrences of each domain name
                domain_name_counts = Counter(domain_names)
                # Find the most frequent domain name
                most_frequent_domain_name = domain_name_counts.most_common(1)
                if most_frequent_domain_name:
                    most_frequent_domain_name = most_frequent_domain_name[0][0]
                    # Check if the most frequent domain name appears in subdomains or path
                    if most_frequent_domain_name in subdomains or most_frequent_domain_name in path:
                        result = 1
                    else:
                        result = 0
                else:
                    result = 0
            else:
                result = 0
            email_features.append(result)

            # Extract PctExtHyperlinks
            for html_string in has_link_group_type:
                try:
                    temp = BeautifulSoup(html_string, 'html.parser')
                except Exception as e:
                    print(f"Error parsing HTML: {e}")
                    continue
                total_links = 0
                external_links = 0
                for link in temp.find_all('a'):
                    href = link.get('href')
                    if href:
                        try:
                            parsed_href = urlparse(href)
                            if parsed_href.scheme in ['http', 'https'] and parsed_href.netloc:
                                domain = tldextract.extract(href).domain
                                if domain != tldextract.extract(html_string).domain:
                                    external_links += 1
                                total_links += 1
                        except ValueError:
                            pass
                if total_links > 0:
                    pct_external_links = external_links / total_links
                    result = round(pct_external_links,9)
                else:
                    result = 0
            email_features.append(result)


            # Extract PctExtResourceUrls
            total_resources = 0
            external_resources = 0
            if not is_safe_url(has_link_group_type[i]):
                print(f"Skipping unsafe URL: {has_link_group_type[i]}")
                continue
            try:
                response = requests.get(has_link_group_type[i], timeout=5)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                print(f"Error fetching URL {has_link_group_type[i]}: {e}")
                continue
            html = response.text
            soup = BeautifulSoup(html, "html.parser")
            tags = soup.find_all(src=True) + soup.find_all(href=True)
            for tag in tags:
                link = tag.get("src") or tag.get("href")
                if link.startswith("http") or link.startswith("https"):
                    # increment the external counter
                    external_resources += 1
            total_resources = len(tags)
            if total_resources > 0:
                percentage = external_resources / total_resources
                percentage = round(percentage,9)
            else:
                percentage = 0
            email_features.append(percentage)

            # Extract ExtFavicon
            for link in temp.find_all('link', rel='icon'):
                href = link.get('href')
                if href:
                    domain = tldextract.extract(href).domain
                    if domain != tldextract.extract(has_link_group_type[i]).domain:
                        result = 1
                    else:
                        result = 0
                else:
                    result = 0
            if len(temp.find_all('link', rel='icon')) == 0:
                result = 0
            #our dataset so far
            email_features.append(result)

            # Extract InsecureForms
            for form in temp.find_all('form'):
                action = form.get('action')
                if action and not action.startswith("#"):
                    parsed_url = urlparse(action)
                    if parsed_url.scheme != "https":
                        result = 1
                    else:
                        result = 0
                else:
                    result = 0
            if len(temp.find_all('form')) == 0:
                result = 0
            email_features.append(result)

            # Extract RelativeFormAction
            for form in temp.find_all('form'):
                action = form.get('action')
                if action and not action.startswith("#"):
                    parsed_url = urlparse(action)
                    if not parsed_url.scheme and not parsed_url.netloc:
                        result = 1
                    else:
                        result = 0
                else:
                    result = 0
            if len(temp.find_all('form')) == 0:
                result = 0
            email_features.append(result)

            # Extract ExtFormAction
            for form in temp.find_all('form'):
                action = form.get('action')
                if action and not action.startswith("#"):
                    domain = tldextract.extract(action).domain
                    if domain != "example" and domain != "localhost":
                        result = 1
                    else:
                        result = 0
                else:
                    result = 0
            if len(temp.find_all('form')) == 0:
                result = 0
            email_features.append(result)

            # Extract AbnormalFormAction
            form_action = "about:blank"
            if form_action == "about:blank":
                result = 1
            elif re.search(r"^javascript:true$", form_action):
                result = 1
            elif re.search(r"^(#|about:blank)$", form_action):
                result = 1
            else:
                result = 0
            email_features.append(result)

            # Extract PctNullSelfRedirectHyperlinks
            total_links = 0
            null_self_redirect_links = 0
            for link in temp.find_all('a'):
                href = link.get('href')
                if href:
                    total_links += 1
                    if href == '#' or href == has_link_group_type[i] or href.startswith('file://'):
                        null_self_redirect_links += 1
            if total_links > 0:
                pct_null_self_redirect_links = null_self_redirect_links / total_links
                result = round(pct_null_self_redirect_links, 9)
            else:
                result = 0
            email_features.append(result)
            
            #Extract FrequentDomainNameMismatch
            links = [link.get("href") for link in temp.find_all("a") if link.get("href")]
            url_domain = tldextract.extract(has_link_group_type[i]).domain
            domains = [tldextract.extract(link).domain for link in links]
            domain_counts = Counter(domains)
            if domain_counts:  # Check if domain_counts is not empty
                most_frequent_domain = domain_counts.most_common(1)[0][0]
                if most_frequent_domain != url_domain:
                    result = 1 
                else:
                    result = 0 
            else:
                result = 0
            email_features.append(result)

            # Extract FakeLinkInStatusBar
            if "onMouseOver" in html_content:
                result = 1 
            else:
                result = 0 
            email_features.append(result)

            # Extract RightClickDisabled
            right_click_pattern = re.compile(r'document\.oncontextmenu\s*=\s*function\s*\(\s*\)\s*{\s*return\s+false;\s*}')
            right_click_disabled = bool(right_click_pattern.search(html_content))
            if right_click_disabled is True:
                result = 1
            else:
                result = 0
            email_features.append(result)

            # Extract PopUpWindow
            if "window.open" in html_content:
                result = 1
            else:
                result = 0
            email_features.append(result)

            # Extract SubmitInfoToEmail
            mailto_links = temp.find_all("a", href=lambda href: href and href.startswith("mailto:"))
            if mailto_links:
                result = 1
            else:
                result = 0
            email_features.append(result)

            # Extract IframeOrFrame
            iframes = temp.find_all('iframe')
            frames = temp.find_all('frame')
            if iframes or frames:
                result = 1
            else:
                result = 0
            email_features.append(result)

            # Extract MissingTitle
            title = temp.find('title')
            if title and not title.string:
                result = 1
            else:
                result = 0
            email_features.append(result)

            # Extract ImagesOnlyInForm
            forms = temp.find_all('form')
            # results = []  # Create a list to store results for each form
            for form in forms:
                if all([img.has_attr('src') for img in form.find_all('img')]) and not form.get_text().strip():
                    result = 1
                else:
                    result = 0
                email_features.append(result)  # Append the result for each form

            # Extract SubdomainLevelRT
            parsed_url = urlparse(has_link_group_type[i])
            subdomain_level = parsed_url.hostname.count('.')
            if subdomain_level == 1:
                result = 1
            elif subdomain_level == 2:
                result = 0
            elif subdomain_level > 2:
                result = -1
            email_features.append(result)

            # Extract UrlLengthRT
            url_length = len(has_link_group_type[i])
            if url_length < 54:
                result = 1
            elif url_length >= 54 and url_length <= 75:
                result = 0
            else:
                result = -1
            email_features.append(result)

            # Extract PctExtResourceUrlsRT
            if not is_safe_url(has_link_group_type[i]):
                print(f"Skipping unsafe URL: {has_link_group_type[i]}")
                continue
            try:
                response = requests.get(has_link_group_type[i], timeout=5)
                response.raise_for_status()
                html = response.text
            except requests.exceptions.RequestException as e:
                print("Failed to download HTML source code")
                result = -1
            else:
                total_resource_urls = 0
                external_resource_urls = 0
                for tag in temp.find_all(['img', 'link', 'script']):
                    url = tag.get('src') or tag.get('href')
                    if url and (url.startswith('http') or url.startswith('//')):
                        domain = tldextract.extract(url).domain
                        if domain != tldextract.extract(has_link_group_type[i]).domain:
                            external_resource_urls += 1
                        total_resource_urls += 1
                if total_resource_urls > 0:
                    pct_external_resource_urls = external_resource_urls / total_resource_urls
                    if pct_external_resource_urls > 10:
                        result = 1
                    else:
                        result = 0
                else:
                    result = -1
            email_features.append(result)

            # Extract AbnormalExtFormActionR
            pattern = re.compile(r'<form.*?\saction=["\'](.*?)["\']', re.IGNORECASE | re.DOTALL)
            matches = pattern.findall(html_content)
            for match in matches:
                if "http" in match and "://" not in match[:10]:
                    result = 1
                elif match.strip() == "about:blank" or not match.strip():
                    result = 1
                else:
                    result = 0
            email_features.append(result)
            
            
            # Extract ExtMetaScriptLinkRT
            soup = BeautifulSoup(html_content, 'html.parser')
            # Find all <meta>, <script>, and <link> tags with href or src attributes
            tags = soup.find_all(['meta', 'script', 'link'], href=True, src=True)
            # Initialize counts
            total_count = len(tags)
            external_count = 0
            for tag in tags:
                href_or_src = tag.get('href') or tag.get('src')
                if "http" in href_or_src and "javascript:" not in href_or_src and not href_or_src.startswith(("#", "about:blank", "file://")):
                    external_count += 1
            # Calculate percentages
            if total_count == 0:
                result = 0
            else:
                external_pct = external_count / total_count
                # Set result based on percentages
                if external_pct >= 0.5:
                    result = 1
                elif external_pct >= 0.1:
                    result = -1
                else:
                    result = 0
            email_features.append(result)

            # Extract PctExtNullSelfRedirectHyperlinksRT
            soup = BeautifulSoup(html_content, 'html.parser')
            # Find all <a> tags with href attributes
            tags = soup.find_all('a', href=True)
            # Initialize counts
            total_links = len(tags)
            external_links = 0
            null_links = 0
            self_redirect_links = 0
            for tag in tags:
                href = tag.get('href')
                if not href:
                    null_links += 1
                elif href.startswith("#") or href.startswith("javascript::void(0)"):
                    null_links += 1
                elif has_link_group_type[i] not in href:
                    external_links += 1
                elif href == has_link_group_type[i] or href == has_link_group_type[i] + "/" or href == has_link_group_type[i] + "#":
                    self_redirect_links += 1
            # Calculate percentages
            if total_links == 0:
                result = 0
            else:
                pct_null_links = null_links / total_links
                pct_external_links = external_links / total_links
                pct_self_redirect_links = self_redirect_links / total_links
                # Set result based on percentages
                if pct_external_links > 0:
                    result = 1
                elif pct_null_links > 0:
                    result = -1
                else:
                    result = 0
            email_features.append(result)

            # CLASS LABEL (49th feature) 
            # this will be done in random forest so we will just put a filler for now (DOES NOT AFFECT PREDICTION)
            email_features.append(0)

    #if there are no links, it's unlikely to be phishing (NOTE: 1 is phishing, 0 is not. I'm not keeping in the Class Label)
    else:
        email_features = {9820,2,1,2,45,0,0,0,0,0,0,0,0,0,0,
                          1,0,0,0,0,0,22,16,0,0,0,0,0.0583941606,0.1666666667,0,
                          0,0,0,0,0.0291970803,0,0,0,0,0,1,0,0,1,1,
                          1,1,0,1}
    # Combine the extracted features into a numpy array
    np.array(email_features)
    #print("Features for Dataset:", email_features)
    #print("All of the Links Datasets: ", multiple_links)

    #check if this runs through each link or just the last link
    return multiple_links





phishing_model = None

def train_model():
    global phishing_model
    print("Training model...")
    # Load and preprocess the dataset
    print("Reading csv file...")
    features = pd.read_csv('src/Phishing_Legitimate_full.csv',sep=',')

    # split the data into label/target and features
    #aka y (THIS SHOULD BE OUR PHISHING/NOT PHISHING COLUMN)
    labels = np.array(features['CLASS_LABEL'])
    #print("LABELS: ", labels)
    #aka x (This should be all of the features)
    features = features.drop('CLASS_LABEL', axis=1)
    #print("FEATURES: ", features)

    #seperate the data into training and testing set
    train_features, test_features, train_labels, test_labels = train_test_split(features, labels, test_size=0.25, random_state=42)
    # Train the RandomForest model classify
    forest = RandomForestClassifier()
    forest.fit(train_features, train_labels)
    phishing_model = forest
    print("Model trained.")

def check_phishing(email_data):
    global phishing_model
    if phishing_model is None:
        train_model()

    email_content = email_data.get('email_contents', '')
    if has_zero_links_and_attachments(email_content):
        print("This email has NO links and appears to be safe.")
        return "This email has zero links. It appears to be safe."
    else:
        print("This email contains links. Checking for phishing.")

    preprocessed_email_content = preprocess_email_content(email_data)

    email_features = transform_email_to_features(preprocessed_email_content)

    phishing_prediction_list = []
    for feature_set in email_features:
        prediction = phishing_model.predict([feature_set])[0]
        phishing_prediction_list.append(prediction)

    if not phishing_prediction_list:
        return "Could not determine if this email is a phishing attempt."

    average = sum(phishing_prediction_list) / float(len(phishing_prediction_list))
    test = str(average)
    phishing_threshold = 0.5
    if average <= phishing_threshold:
        return "This is a phishing attempt. Report this immediately.  Prediction: " + test
    else:
        return "This email appears to be authentic and trustworthy. Prediction: " + test

def check_phishing_url(url):
    global phishing_model
    if phishing_model is None:
        train_model()

    features = transform_url_to_features(url)
    if not features:
        return "Could not process the URL."

    prediction = phishing_model.predict([features])[0]

    if prediction == 1:
        return "This URL is potentially malicious."
    else:
        return "This URL appears to be safe."

def transform_url_to_features(url):
    # This is a simplified version of transform_email_to_features
    # It extracts features for a single URL

    # For now, we will just extract a few features as a placeholder
    # The full feature extraction logic should be refactored to be reusable

    email_features = []

    # UrlLength
    email_features.append(len(url))

    # NumDots
    email_features.append(url.count("."))

    # ... add more feature extraction here ...
    # This is a placeholder for the full feature extraction logic.
    # For the purpose of this refactoring, we will return a dummy list of features
    # to make the backend work.

    # In a real implementation, we would refactor the feature extraction logic
    # from transform_email_to_features into smaller, reusable functions
    # and call them here.

    # Dummy features to match the model's expected input
    # The model was trained on 48 features.
    dummy_features = [0] * 48
    dummy_features[0] = len(url)
    dummy_features[1] = url.count(".")

    return dummy_features
        




def has_zero_links_and_attachments(email_content):
    # Check for links
    link_pattern = re.compile(r'https?://\S+')
    links = re.findall(link_pattern, email_content)

    # Check for attachments
    # You may need to define your own logic to detect attachments based on your email format
    # For example, you can look for keywords like "attachment" or "file"
    attachment_keywords = ["attachment", "file"]
    has_attachments = any(keyword in email_content.lower() for keyword in attachment_keywords)

    # Return True if there are zero links and zero attachments, otherwise False
    print(len(links), not has_attachments)
    return len(links) == 0 and not has_attachments