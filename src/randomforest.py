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

def preprocess_email_content(email_content):
    print("Preprocessing email contents...")
    extracted = email_content['email_contents']
    preprocessed_content = extracted.lower()
    return preprocessed_content

def transform_email_to_features(preprocessed_content):
    print("In function transform_email_to_features")

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
    print("This is the length of has_link_group_type: " + str(len(has_link_group_type)))
    print("These are all the links in that list: ")
    for site in range (0, len(has_link_group_type)):
        print("Link ", site+1, ": ", has_link_group_type[site])
    #get a list of all of the links in the email
    if match and (len(has_link_group_type) != 0):
        #check each website for sub-categories (ex: id, subdomain, etc.)
        for i in range(0, len(has_link_group_type)):
            #expecting multiple links in the email
            if len(email_features) != 0:
                multiple_links.append(email_features)
            email_features.clear()
            print("List of All Email Features so Far: ")
            print("**should end with a total of ", len(has_link_group_type)," email_features lists within the list**")
            
            print("================================================================")
            print("                  STARTING TO FIND SUBCATEGORIES                ")
            print("================================================================")
            #print current link we are on
            print("Current link we are on: ", i+1)
            #print the number we are on
            print("Current num for i: ", i)
            #print the link we are curently on
            print("Current link: ", has_link_group_type[i])
            # GET request to URL
            response = requests.get(has_link_group_type[i])
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
            print("EXTRACT ID from ", has_link_group_type[i])
            try:
                id = re.findall('/(\d+)\/|ID=(\d+/g)',has_link_group_type[i])[0]
             # id doesnt-'t exist    
            except:
                id = 0
            email_features.append(int(id))
            print("ID:", id)
            print("-------- Features for Dataset so Far --------\n", email_features)
            
            # Extract NumDots from preprocessed_email_content
            print("EXTRACT NUMBER OF DOTS from ", has_link_group_type[i])
            num_dots = has_link_group_type[i].count(".")
            # Handle invalid dots at end of domain name extension    
            ext = tldextract.extract(has_link_group_type[i]) #extracting
            extension = ext.suffix
            if extension[-1] == '.': #checks if the last character in the array is '.' as in careers.csulb.edu. where an invalid '.' is appended to the end of the URL
             num_dots -= 1 #subtracts that from the total
            email_features.append(num_dots) 
            print("Amount of Dots in the link: ", num_dots)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract SubdomainLevel, number is btw 0 - 126
            print("EXTRACT SUBDOMAIN LEVEL")
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
            print("Sub Domain: ", sub_parts) #subparts is the array of subdomains split up by '.'
            print("Sub Domain Level:", sublvl) #sublvl is the number of subdomains
            email_features.append(sublvl)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract PathLevel
            print("EXTRACT PATH LEVEL")
            path_segments = has_link_group_type[i].split('/')
            path_level = len([segment for segment in path_segments if segment])  # Count non-empty segments
            email_features.append(path_level)
            print("Path Level: ", path_level)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract UrlLength
            print("EXTRACT URL LENGTH")
            email_features.append(len(has_link_group_type[i]))
            print("Url: ", has_link_group_type[i])
            print("Url Length: ", len(has_link_group_type[i]))
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract NumDash
            print("EXTRACT NUMBER OF - SYMBOL")
            num_dash = has_link_group_type[i].count("-")
            email_features.append(num_dash)
            print("Amount of Dashes: ", num_dash)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract NumDashInHostname
            print("EXTRACT NUMBER OF - SYMBOL IN HOST NAME")
            print("Url: ", has_link_group_type[i])
            hostname = re.findall(r'https?://([^/]+)', has_link_group_type[i])[0]
            print("Hostname: ", hostname)
            num_dash_in_domain = hostname.count("-")
            email_features.append(num_dash_in_domain)
            print("Amount of Dashes in Host Domain: ", num_dash_in_domain)
            print("-------- Features for Dataset so Far --------\n", email_features)
            
            # Extract AtSymbol
            print("EXTRACT NUMBER OF @ SYMBOL")
            if "@" in has_link_group_type[i]:
                print("@ symbol found in URL")
                result = 1
            else:
                print("@ symbol not found in URL")
                result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)
            
            # Extract TildeSymbol
            print("EXTRACT NUMBER OF ~ SYMBOL")
            if "~" in has_link_group_type[i]:
                print("Tilde symbol found in URL")
                result = 1
            else:
                print("Tilde symbol not found in URL")
                result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract NumUnderscore
            print("EXTRACT NUMBER OF _ SYMBOL")
            num_underscore = has_link_group_type[i].count("_")
            email_features.append(num_underscore)
            print("Amount of Underscore in Url: ", num_underscore)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract NumPercent from preprocessed_email_content
            print("EXTRACT NUMBER OF % SYMBOL")
            num_percent = has_link_group_type[i].count("%")
            email_features.append(num_percent)
            print("Amount of Percent Symbol Found in Url: ", num_percent)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Queries are after "?" and separated by "&" or "+" until the end of string
            # A Queries starts with a key, has '=' as a seperater, and the values after it
            # r"(\w+)=(\w+)"
            # (\w+) finds all sequences of one or more char (this is the key, usually it is 'q' but it can be a word like 'query')
            # followed by '=' 
            # followed by (\w+) which are more characters (these are the values of the query)
            # example of query of 2 components: https://example.com/page?parameter1=x&parameter2=y
            # queries are parameter1=x and parameter2=y, it would look like this [(parameter1,x), (parameter2=y)]
            # Extract NumQueryComponents
            print("NUMBER OF QUERY COMPONENTS")
            queries = re.findall(r"(\w+)=(\w+)", has_link_group_type[i])
            query_length = len(queries)
            email_features.append(query_length)
            print("Query List: ", queries)
            print("Number of Queries: ", len(queries))
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract NumAmpersand
            print("EXTRACT NUMBER OF & SYMBOLS")
            num_ampersand = has_link_group_type[i].count("&")
            email_features.append(num_ampersand)
            print("Amount of Ampersand: ", num_ampersand)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract NumHash
            print("EXTRACT NUMBER OF # SYMBOLS")
            num_hash = has_link_group_type[i].count("#")
            email_features.append(num_hash)
            print("Amount of Hash: ", num_hash)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract NumNumericChars
            print("EXTRACT NUMBER OF NUMERICAL CHARACTERS")
            num_numeric_chars = sum(c.isdigit() for c in has_link_group_type[i])
            email_features.append(num_numeric_chars)
            print("Amount of Numeric Characters: ", num_numeric_chars)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract NoHttps
            print("CHECK IF THERE ARE ANY HTTPS")
            match = re.search(r"^https", has_link_group_type[i])
            if match:
                print("https found in URL")
                result = 1
            else:
                print("https not found in URL")
                result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract RandomString
            # find if there is a random string in the link
            # Note: "Random strings in links: creating unique identifiers, preventing caching, or adding security."
            # [a-zA-Z0-9] any sequence of lowercase, lower can uppercase, letters and numbers, and numbers
            # {8,} = any sequence of at least 8
            # matches returns a list of random strings that are found in the link
            print("CHECK IF THERE IS A RANDOM/UNQIE STRING")
            matches = re.findall(r"[a-zA-Z0-9]{6,}", has_link_group_type[i], re.IGNORECASE)
            #if there is a random string
            if len(matches) > 0:
                #return true
                result = 1
                print("Random string found")
            else:
                #if there is none, return false
                result = 0
                print("Random string not found")
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract IpAddress
            print("EXTRACT THE ID ADDRESS")
            # Define the regular expression
            regex = r"^ (http|https)://\d+\.\d+\.\d+\.\d+\.*"
            # Compile the regular expression
            pattern = re.compile(regex)
            # Test if the URL matches the regular expression
            if pattern.match(has_link_group_type[i]):
                # Return 0 if true
                print("IP Address is in Link")
                ip_address =  0
            else:
                # Return 1 if false
                print("IP Address is not in Link")
                ip_address = 1
            print("IP Address: ", ip_address)
            email_features.append(ip_address)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract DomainInSubdomains
            print("CHECK IF DOMAIN IS IN THE SUBDOMAIN")
            parsed_url = urlparse(has_link_group_type[i])
            domain = tldextract.extract(parsed_url.netloc).domain
            result = 0
            for check in range(len(sub_parts)):
                if domain == sub_parts[check]:
                    print("Domain is used in the subdomain.")
                    print("Domain: ", domain, "     Subdomain: ", subdomain)
                    result = 1
                else:
                    print("Domain is not used in the subdomain.")
                    result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract DomainInPaths
            print("CHECK IF THE DOMAIN IS IN THE PATHS")
            parsed_url = urlparse(has_link_group_type[i])
            domain = tldextract.extract(parsed_url.netloc).domain
            paths = parsed_url.path
            # default is domain is not found in path
            result = 0
            # check through each path
            for path in paths.split("/"):
                if domain in path:
                    print("Domain was found in path")
                    result = 1
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract HttpsInHostname
            print("CHECK IF HTTPS IS IN THE HOSTNAME")
            parsed_url = urlparse(has_link_group_type[i])
            if parsed_url and parsed_url.hostname:
                hostname = parsed_url.hostname
                if "https" in hostname.lower() and not hostname.startswith("https"):
                    print("HTTPS is obfuscated in the hostname.")
                    result = 1
                else:
                    print("HTTPS is not obfuscated in the hostname.")
                    result = 0
            else:
                print("Invalid URL.")
                result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract HostnameLength
            print("EXTRACT THE LENGTH OF THE HOSTNAME")
            parsed_url = urlparse(has_link_group_type[i])
            if parsed_url.hostname:
                hostname = parsed_url.hostname
                hostname_length = len(hostname)
                email_features.append(hostname_length)
                print("Hostname: ", hostname, "   Length: ", hostname_length)
                # The dataset so far
                print("-------- Features for Dataset so Far --------\n", email_features)
            else:
                print("Invalid URL.")

            # Extract PathLength
            # max url length is usually under 2000, bc not all browsers can work over it
            # this means anything over is suspisious.
            #r"(?<=/)[^?#]*" finds sequences that does not contain ? or #, and is preceded by a /
            print("EXTRACT THE LENGTH OF THE PATH")
            path_length = len(re.findall(r"(?<=/)[^?#]*", has_link_group_type[i]))
            email_features.append(path_length)
            print("Path Length: ", path_length)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract QueryLength
            # using the same example: https://example.com/page?parameter1=x&parameter2=y
            # urlparse(has_link_group_type[0]).query returns "parameter1=x&parameter2=y"
            # so we use len to get the length of that query string
            print("EXTRACT THE LENGTH OF THE QUERY")
            parsed_url = urlparse(has_link_group_type[i])
            query_length = len(parsed_url.query)
            email_features.append(query_length)
            print("-------- Features for Dataset so Far --------\n", email_features)
            
            # Extract DoubleSlashInPath
            #if there are double slashes in the the path, return 1
            print("CHECK IF THERE ARE // in PATH")
            parsed_url = urlparse(has_link_group_type[i])
            if re.search("//", parsed_url.path):
                print("// exists in the path.")
                result = 1
            #else there are not then return 0
            else:
                print("// does not exist in the path.")
                result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)
            
            # Extract NumSensitiveWords
            print("EXTRACT THE NUMBER OF TIME SENSITIVE WORDS SHOWS UP IN THE LINK")
            # list of sensitive words
            sensitive_words = ["secure", "account", "webscr", "login", "ebayisapi", "signin", "banking", "confirm"]
            # sum of amount of sensitive words
            num_sensitive_words = sum([1 for word in sensitive_words if re.search(word, has_link_group_type[i], re.IGNORECASE)])
            email_features.append(num_sensitive_words)
            print("Amount of Sensitive Words: ", num_sensitive_words)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract EmbeddedBrandName
            print("CHECK IF THE BRANDNAME IS EMBEDDED")
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
                        print("Brand name embedded")
                    else:
                        result = 0
                        print("Brand name not embedded")
                else:
                    result = 0
                    print("No frequent domain name found in links")
            else:
                print("Error: could not extract hostname from URL")
                result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract PctExtHyperlinks
            print("FIND THE PERCENTAGE OF ExtHyperLinks")
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
                    print(f"Percentage of external hyperlinks: ", external_links, " / ", total_links, " = ", pct_external_links)
                    result = round(pct_external_links,9)
                else:
                    print("No hyperlinks found in HTML")
                    result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)


            # Extract PctExtResourceUrls
            print("EXTRACT THE PERCENT OF EXT RESOURCES IN THE URL")
            total_resources = 0
            external_resources = 0
            response = requests.get(has_link_group_type[i])
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
                print("Pct of Ext Resouce in Url: ", external_resources, " / ", total_resources, " = ", percentage)
            else:
                percentage = 0
            email_features.append(percentage)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract ExtFavicon
            print("EXTRACT EXTERNAL FAVICON")
            for link in temp.find_all('link', rel='icon'):
                href = link.get('href')
                if href:
                    domain = tldextract.extract(href).domain
                    if domain != tldextract.extract(has_link_group_type[i]).domain:
                        print(f"External favicon found: {href}")
                        result = 1
                    else:
                        print("External favicon not found")
                        result = 0
                else:
                    result = 0
            if len(temp.find_all('link', rel='icon')) == 0:
                result = 0
            #our dataset so far
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract InsecureForms
            print("CHECK FOR INSECURE FORM ACTION")
            for form in temp.find_all('form'):
                action = form.get('action')
                if action and not action.startswith("#"):
                    parsed_url = urlparse(action)
                    if parsed_url.scheme != "https":
                        print(f"Insecure form action found: {action}")
                        result = 1
                    else:
                        print("Insecure form action not found")
                        result = 0
                else:
                    result = 0
            if len(temp.find_all('form')) == 0:
                result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract RelativeFormAction
            print("CHECK RELATIVE FORM ACTION")
            for form in temp.find_all('form'):
                action = form.get('action')
                if action and not action.startswith("#"):
                    parsed_url = urlparse(action)
                    if not parsed_url.scheme and not parsed_url.netloc:
                        print(f"Relative form action found: {action}")
                        result = 1
                    else:
                        print("Relative form action not found")
                        result = 0
                else:
                    result = 0
            if len(temp.find_all('form')) == 0:
                result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract ExtFormAction
            print("CHECK EXTERNAL FORM ACTION")
            for form in temp.find_all('form'):
                action = form.get('action')
                if action and not action.startswith("#"):
                    domain = tldextract.extract(action).domain
                    if domain != "example" and domain != "localhost":
                        print(f"External form action found: {action}")
                        result = 1
                    else:
                        print("External form action not found")
                        result = 0
                else:
                    result = 0
            if len(temp.find_all('form')) == 0:
                result = 0
            email_features.append(result)
            #our dataset so far
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract AbnormalFormAction
            print("CHECK FOR ABNORMAL FORM ACTION")
            form_action = "about:blank"
            if form_action == "about:blank":
                print("Form action is about:blank")
                result = 1
            elif re.search(r"^javascript:true$", form_action):
                print("Form action contains javascript:true")
                result = 1
            elif re.search(r"^(#|about:blank)$", form_action):
                print("Form action contains # or about:blank")
                result = 1
            else:
                print("Normal form action")
                result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract PctNullSelfRedirectHyperlinks
            print("FIND PERCENTAGE OF HYPERLINKS CONTAINING NULL")
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
                print(f"Percentage of hyperlinks containing empty value, self-redirect value, or abnormal value: {round(pct_null_self_redirect_links, 9)}")
                result = round(pct_null_self_redirect_links, 9)
            else:
                print("No hyperlinks found in HTML")
                result = 0
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)
            
            #Extract FrequentDomainNameMismatch
            print("EXTRACT FREQUENT DOMAIN NAME MISMATCH")
            links = [link.get("href") for link in temp.find_all("a") if link.get("href")]
            url_domain = tldextract.extract(has_link_group_type[i]).domain
            domains = [tldextract.extract(link).domain for link in links]
            domain_counts = Counter(domains)
            if domain_counts:  # Check if domain_counts is not empty
                most_frequent_domain = domain_counts.most_common(1)[0][0]
                if most_frequent_domain != url_domain:
                    result = 1 
                    print("Frequent domain name mismatch found")
                else:
                    result = 0 
                    print("Frequent domain name mismatch not found")
            else:
                result = 0
                print("No domains found in links")
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract FakeLinkInStatusBar
            print("EXTRACT FAKE LINK IN STATUS BAR")
            if "onMouseOver" in html_content:
                result = 1 
                print("Fake link in status bar found")
            else:
                result = 0 
                print("Fake link in status bar not found")
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract RightClickDisabled
            print("CHECK IF RIGHT CLICK DISABLED")
            right_click_pattern = re.compile(r'document\.oncontextmenu\s*=\s*function\s*\(\s*\)\s*{\s*return\s+false;\s*}')
            right_click_disabled = bool(right_click_pattern.search(html_content))
            if right_click_disabled is True:
                result = 1
                print("Right click disabled: Yes")
            else:
                result = 0
                print("Right click disabled: No")
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract PopUpWindow
            print("CHECK IF THERE IS POP UP WINDOW")
            if "window.open" in html_content:
                result = 1
                print("Pop Up Window: Yes")
            else:
                result = 0
                print("Pop Up Window: No")
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract SubmitInfoToEmail
            print("SUBMIT INFO TO EMAIL")
            mailto_links = temp.find_all("a", href=lambda href: href and href.startswith("mailto:"))
            if mailto_links:
                result = 1
                print("Submit Info To Email: Yes")
            else:
                result = 0
                print("SubmitInfoToEmail: No")
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract IframeOrFrame
            print("CHECK IF IFRAME OR FRAME FOUND")
            iframes = temp.find_all('iframe')
            frames = temp.find_all('frame')
            if iframes or frames:
                result = 1
                print("Iframe or frame found")
            else:
                result = 0
                print("Iframe or frame not found")
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract MissingTitle
            print("CHECK IF TITLE IS MISSING")
            title = temp.find('title')
            if title and not title.string:
                result = 1
                print("Empty Title found")
            else:
                result = 0
                print("Title not found or empty")
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract ImagesOnlyInForm
            print("EXTRACT IMAGE ONLY IN FORM")
            forms = temp.find_all('form')
            # results = []  # Create a list to store results for each form
            for form in forms:
                if all([img.has_attr('src') for img in form.find_all('img')]) and not form.get_text().strip():
                    result = 1
                    print("Images only in form")
                else:
                    result = 0
                    print("Text found in form")
                email_features.append(result)  # Append the result for each form
            # email_features.extend(results)  # Append all results to email_features
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract SubdomainLevelRT
            print("CHECK IF SUBDOMAIN LEVEL FITS RULES AND THRESHOLDS")
            parsed_url = urlparse(has_link_group_type[i])
            subdomain_level = parsed_url.hostname.count('.')
            if subdomain_level == 1:
                print("SubDomain Level Rules and Thresholds: Legitimate")
                result = 1
            elif subdomain_level == 2:
                print("SubDomain LevelURL Length Rules and Thresholds: Suspicious")
                result = 0
            elif subdomain_level > 2:
                print("SubDomain Level Rules and Thresholds: Phishing")
                result = -1
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract UrlLengthRT
            print("CHECK IF THE URL LENGTH FITS THE RULES AND THRESHOLDS")
            url_length = len(has_link_group_type[i])
            if url_length < 54:
                print("URL Length Rules and Thresholds: Legitimate")
                result = 1
            elif url_length >= 54 and url_length <= 75:
                print("URL Length Rules and Thresholds: Suspicious")
                result = 0
            else:
                print("URL Length Rules and Thresholds: Phishing")
                result = -1
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract PctExtResourceUrlsRT
            print("CHECK IF PERCENTAGE OF EXTERNAL RESOURCES URLS FITS RULES AND THRESHOLD")
            try:
                response = requests.get(has_link_group_type[i], timeout=5)
                html = response.text
            except:
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
                    print(f"Percentage of external resource URLs: {round(pct_external_resource_urls,9)}")
                else:
                    print("No resource URLs found in HTML")
                    result = -1
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract AbnormalExtFormActionR
            print("EXTRACT ABNORMAL EXTERNAL FORM ACTION RULES")
            pattern = re.compile(r'<form.*?\saction=["\'](.*?)["\']', re.IGNORECASE | re.DOTALL)
            matches = pattern.findall(html_content)
            for match in matches:
                if "http" in match and "://" not in match[:10]:
                    result = 1
                    print("Has foreign domain")
                elif match.strip() == "about:blank" or not match.strip():
                    result = 1
                    print("Has about:blank, or empty string")
                else:
                    result = 0
                    print("Normal form action attribute")
            email_features.append(result)
            print("-------- Features for Dataset so Far --------\n", email_features)
            
            
            # Extract ExtMetaScriptLinkRT
            print("CHECK IF EXTERNAL META SCRIPT LINK FITS RULE AND THRESHOLD")
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
            print("Percentage of external Meta/Script/Link tags: ", result)
            print("-------- Features for Dataset so Far --------\n", email_features)

            # Extract PctExtNullSelfRedirectHyperlinksRT
            print("CHECK IF PctExtNullSelfRedirectHyperlinks FITS RULES AND THRESHOLD")
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
            print("Percentage of hyperlinks in HTML source code: ", result)
            print("-------- Features for Dataset so Far --------\n", email_features)

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





def check_phishing(email_data):
    email_content = email_data.get('email_contents', '')
    if has_zero_links_and_attachments(email_content):
        print("This email has NO links and appears to be safe.")
        return "This email has zero links. It appears to be safe."
    else:
        print("This email contains links. Checking for phishing.")
        #return "This email has links and/ or attachments."
    # Get the currently open email in Outlook
    #email_content = email_data
    # Preprocess the email content
    preprocessed_email_content = preprocess_email_content(email_data)
    print(preprocessed_email_content)

    # Transform the preprocessed email content into a format compatible with the random forest model
    email_features = transform_email_to_features(preprocessed_email_content)
    # RANDOM FOREST ALGORITHM
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

    # Train features,x
    #print("Train Features: ", train_features)
    # Train labels, y
    #print("Train Labels: ", train_labels)
    # Test features, x
    #print("Test Features: ", test_features)
    # Test labels, y
    #print("Test Labels: ", test_labels)

    # Predict if the email is a phishing attempt using the random forest model
    # List of Phishing Predictions
    phishing_prediction_list = []
    # Phishing Prediction for each email
    for i in range(len(email_features)):
        single_email_with_its_features = email_features[i]
        # this is the class label (49th feature)
        phishing_prediction = forest.predict([single_email_with_its_features])[0]
        print("Phishing Prediction for Email ", i+1, ": ", phishing_prediction)
        phishing_prediction_list.append(phishing_prediction)

    # phishing prediction should output a lost of the features with it's pediction
    # of whether it's phishing or not
    # ex: [0 , 1, 0, 0, 0, 1, 0, 0, 0,..., 0]
    # Set a threshold for the prediction to classify it as phishing or not
    average = sum(phishing_prediction_list) / float(len(phishing_prediction_list))
    test = str(average)
    phishing_threshold = 0.5
    if average <= phishing_threshold:
        print("This email may be a phishing attempt. Prediction: " + test)
        return "This is a phishing attempt. Report this immediately.  Prediction: " + test
    else:
        print("This email seems legitimate. Prediction: " + test)
        return "This email appears to be authentic and trustworthy. Prediction: " + test
        




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