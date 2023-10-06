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
import ipaddress
from sklearn.ensemble import RandomForestClassifier
import statistics as stats
import email

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

    #check if there are links
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
    #get a list of all of the links in the email
    if match and (len(has_link_group_type) != 0):
        #check each website for sub-categories (ex: id, subdomain, etc.)
        for i in range(0, len(has_link_group_type)):
            #print the number we are on
            print("Number for i: ", i)
            #print the link we are curently on
            print("Current link: ", has_link_group_type[i])
            # GET request to URL
            response = requests.get(has_link_group_type[i])
            # pasrse HTML content
            temp = BeautifulSoup(response.content, 'html.parser')
            html_content = response.text

            #expecting multiple links in the email
            if len(email_features) != 0:
                multiple_links.append(email_features)
            email_features.clear()

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
            print("List of URLs:")
            print(has_link_group_type)
            try:
                id = re.findall('/(\d+)\/|ID=(\d+/g)',has_link_group_type[i])[0]
             # id doesnt-'t exist    
            except:
                id = 0
            email_features.append(int(id))
            print("ID:", id)
            print("Features for Dataset so Far: ", email_features)
            
            # Extract NumDots from preprocessed_email_content
            num_dots = has_link_group_type[i].count(".")
            # Handle invalid dots at end of domain name extension    
            ext = tldextract.extract(has_link_group_type[i]) #extracting
            extension = ext.suffix
            if extension[-1] == '.': #checks if the last character in the array is '.' as in careers.csulb.edu. where an invalid '.' is appended to the end of the URL
             num_dots -= 1 #subtracts that from the total
            email_features.append(num_dots) 
            print("Amount of Dots in the link: ", num_dots)

            #TODO: Check if this correct
            # Extract SubdomainLevel, number is btw 0 - 126
            ext = tldextract.extract(has_link_group_type[i]) #https://pypi.org/project/tldextract/
            subdomain = ext.subdomain
            sub_parts = subdomain.split('.')
            # Remove port  
            if ":" in subdomain:
              subdomain = subdomain.split(":")[0]
            # check if empty subdomain, set to empty 
            if not subdomain:
                sub_parts = []

            sub_parts = subdomain.split(".")

            if len(sub_parts) < 1: 
                sublvl = 0
            else:
             sublvl = len(sub_parts)
            email_features.append(sublvl)
            print("Sub Domain: ", sub_parts) #subparts is the array of subdomains split up by '.'
            print("Subdomain Level:", sublvl) #sublvl is the number of subdomains


            #TODO: REDO, incorrect
            # # Extract PathLevel
            # # parsed_url = urlparse(has_link_group_type[i])
            # # path = parsed_url.path
            # path_level = has_link_group_type[i].split('/')
            # # path_level = len(path_segments) - 1
            # email_features.append(path_level)
            # print("Pathlevel: ", path_level)

            # Extract UrlLength
            email_features.append(len(has_link_group_type[i]))
            print("Url: ", has_link_group_type[i])
            print("Url Length: ", len(has_link_group_type[i]))

            # Extract NumDash from preprocessed_email_content
            num_dash = has_link_group_type[i].count("-")
            email_features.append(num_dash)
            print("Amount of Dashes: ", num_dash)

            # Extract NumDashInHostname
            hostname = re.findall(r'https?://([^/]+)', has_link_group_type[i])[0]
            num_dash_in_domain = hostname.count("-")
            email_features.append(num_dash_in_domain)
            print("Hostname: ", hostname)
            print("Amount of Dashes in Host Domain: ", num_dash_in_domain)
            
            # Extract AtSymbol
            if "@" in has_link_group_type[i]:
                print("At symbol found in URL")
                result = 1
            else:
                print("At symbol not found in URL")
                result = 0
            email_features.append(result)
            
            # Extract TildeSymbol
            if "~" in has_link_group_type[i]:
                print("Tilde symbol found in URL")
                result = 1
            else:
                print("Tilde symbol not found in URL")
                result = 0
            email_features.append(result)

            # Extract NumUnderscore from preprocessed_email_content
            num_underscore = has_link_group_type[i].count("_")
            email_features.append(num_underscore)
            print("Amount of Underscore in Url: ", num_underscore)
            print("Features for Dataset so Far: ", email_features)

            # Extract NumPercent from preprocessed_email_content
            num_percent = has_link_group_type[i].count("%")
            email_features.append(num_percent)
            print("Amount of Percent Symbol Found in Url: ", num_percent)

            #TODO: Fix, starts with "?" and separated by "&" until the end of string, 
            #       example of query of 2 components: https://example.com/page?parameter1=x&parameter2=y
            # #Extract NumQueryComponents
            # num_query_components = has_link_group_type[i].count("?")
            # email_features.append(num_query_components)
            # print("Amount of Queries: ", num_query_components)

            # Extract NumAmpersand from preprocessed_email_content
            num_ampersand = has_link_group_type[i].count("&")
            email_features.append(num_ampersand)
            print("Amount of Ampersand: ", num_ampersand)

            # Extract NumHash from preprocessed_email_content
            num_hash = has_link_group_type[i].count("#")
            email_features.append(num_hash)
            print("Amount of Hash: ", num_hash)

            #TODO: Check if corect
            # # Extract NumNumericChars from preprocessed_email_content
            # num_numeric_chars = sum(c.isdigit() for c in has_link_group_type[i])
            # email_features.append(num_numeric_chars)
            # print("Amount of Numeric Characters: ", num_numeric_chars)

            # Extract NoHttps
            match = re.search(r"^https", has_link_group_type[i])
            if match:
                print("https found in URL")
                result = 1
            else:
                print("https not found in URL")
                result = 0
            email_features.append(result)

            #########################################################################################################
            # COMMENTED OUT BELOW TO TEST EACH FUNCTION IF CORRECT/WRONG, above this is correct/partially looked over
            #########################################################################################################

            # # Extract RandomString
            # pattern = r"[a-z0-9]{8,}"
            # matches = re.findall(pattern, has_link_group_type[i])
            # if matches:
            #     result = 1
            #     print("Random string found")
            # else:
            #     result = 0
            #     print("Random string not found")
            # email_features.append(result)
            # #the dataset so far
            # print("Features for Dataset so Far: ", email_features)

            # # Extract IpAddress
            # email_message = email.message_from_string(preprocessed_content)
            # header_value = email_message.get('Received', '')
            # ip_address = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', header_value)
            # hostname = ip_address
            # try:
            #     ipaddress.ip_address(hostname)
            #     print("The hostname is an IP address.")
            #     result = 1
            # except ValueError:
            #     print("The hostname is not an IP address.")
            #     result = 0
            # email_features.append(result)

            # # Extract DomainInSubdomains
            # subdomain, _, tld = tldextract.extract(has_link_group_type[i])
            # if tld in subdomain:
            #     print("The TLD or ccTLD is used in the subdomain.")
            #     result = 1
            # else:
            #     print("The TLD or ccTLD is not used in the subdomain.")
            #     result = 0
            # email_features.append(result)

            # # Extract DomainInPaths
            # path = urlparse(has_link_group_type[i]).path
            # if '/' in path:
            #     domain = path.split('/')[1]
            #     tld = tldextract.extract(domain).suffix
            # else:
            #     tld = tldextract.extract(path).suffix
            # if tld:
            #     print("The TLD or ccTLD is used in the path.")
            #     result = 1
            # else:
            #     print("The TLD or ccTLD is not used in the path.")
            #     result = 0
            # email_features.append(result)

            # # Extract HttpsInHostname
            # parsed_url = urlparse(has_link_group_type[i])
            # if parsed_url:
            #     hostname = parsed_url.hostname
            #     if hostname and re.search(r"https", hostname):
            #         print("HTTPS is obfuscated in the hostname.")
            #         result = 1
            #     else:
            #         print("HTTPS is not obfuscated in the hostname.")
            #         result = 0
            # else:
            #     print("Invalid URL.")
            #     result = 0
            # email_features.append(result)

            # #our dataset so far
            # print("Features for Dataset so Far: ", email_features)

            # # Extract HostnameLength
            # hostname = re.findall(r'https?://([^/]+)', has_link_group_type[i])[0]
            # email_features.append(len(hostname))
            # print("Hostname: ", hostname)
            # #our dataset so far
            # print("Features for Dataset so Far: ", email_features)

            # # Extract PathLength
            # path = urlparse(has_link_group_type[i])
            # email_features.append(len(path))
            # print("Path: ", path)
            # #our dataset so far
            # print("Features for Dataset so Far: ", email_features)

            # # Extract QueryLength
            # queries = has_link.split("?")
            # query_length = 0
            # for i in queries[1:]:
            #     query_length = query_length + len(queries[i])
            # email_features.append(query_length)
            # print("Query List: ", queries)
            
            # # Extract DoubleSlashInPath
            # parsed_url = urlparse(has_link_group_type[i])
            # path = parsed_url.path
            # if re.search(r"\/\/", path):
            #     print("// exists in the path.")
            #     result = 1
            # else:
            #     print("// does not exist in the path.")
            #     result = 0
            # email_features.append(result)
            
            # # Extract NumSensitiveWords
            # sensitive_words = ["secure", "account", "webscr", "login", "ebayisapi", "signin", "banking", "confirm"]
            # num_sensitive_words = sum([1 for word in sensitive_words if re.search(word, has_link_group_type[i], re.IGNORECASE)])
            # email_features.append(num_sensitive_words)
            # print("Amount of Senstive Words: ", num_sensitive_words)

            # #TODO: Fix "Found missing data: 'in <string>' requires string as left operand, not NoneType"
            # # Extract EmbeddedBrandName
            # parsed_url = urlparse(has_link_group_type[i])
            # if parsed_url.hostname is not None:
            #     subdomains = parsed_url.hostname.split(".")[:-2]
            #     path = parsed_url.path
            #     domain_names = [urlparse(link.get("href")).hostname for link in temp.find_all("a") if link.get("href")]
            #     domain_name_counts = Counter(domain_names)
            #     most_frequent_domain_name = domain_name_counts.most_common(1)[0][0]
            #     if most_frequent_domain_name in subdomains or most_frequent_domain_name in path:
            #         result = 1
            #         print("Brand name embedded")
            #     else:
            #         result = 0
            #         print("Brand name not embedded")
            # else:
            #     print("Error: could not extract hostname from URL")
            #     result = 0
            # email_features.append(result)

            # # Extract PctExtHyperlinks
            # if has_link:
            #     total_links = 0
            #     external_links = 0
            #     for link in temp.find_all('a'):
            #         href = link.get('href')
            #         if href:
            #             try:
            #                 parsed_href = urlparse(href)
            #                 if parsed_href.scheme in ['http', 'https'] and parsed_href.netloc:
            #                     domain = tldextract.extract(href).domain
            #                     if domain != tldextract.extract(has_link).domain:
            #                         external_links += 1
            #                     total_links += 1
            #             except ValueError:
            #                 pass
            #     if total_links > 0:
            #         pct_external_links = external_links / total_links
            #         print(f"Percentage of external hyperlinks: {round(pct_external_links, 2)}")
            #         result = round(pct_external_links, 2)
            #     else:
            #         print("No hyperlinks found in HTML")
            #         result = 0
            #     email_features.append(result)

            # # Extract PctExtResourceUrls
            # total_resources = 0
            # external_resources = 0
            # for tag in temp.find_all():
            #     if tag.has_attr('href'):
            #         href = tag['href']
            #         if href.startswith('http') or href.startswith('//'):
            #             domain = tldextract.extract(href).domain
            #             if domain != tldextract.extract(has_link_group_type[i]).domain:
            #                 external_resources += 1
            #         total_resources += 1
            #     if tag.has_attr('src'):
            #         src = tag['src']
            #         if src.startswith('http') or src.startswith('//'):
            #             domain = tldextract.extract(src).domain
            #             if domain != tldextract.extract(has_link_group_type[i]).domain:
            #                 external_resources += 1
            #         total_resources += 1
            # if total_resources > 0:
            #     pct_external_resources = (external_resources / total_resources) * 100
            #     print(f"Percentage of external resource URLs: {round(pct_external_resources, 2)}")
            #     result = round(pct_external_resources, 2)
            # else:
            #     print("No resource URLs found in HTML")
            #     result = 0
            # email_features.append(result)

            # # Extract ExtFavicon
            # for link in temp.find_all('link', rel='icon'):
            #     href = link.get('href')
            #     if href:
            #         domain = tldextract.extract(href).domain
            #         if domain != tldextract.extract(has_link_group_type[i]).domain:
            #             print(f"External favicon found: {href}")
            #             email_features.append(1)
            #         else:
            #             print("External favicon not found")
            #             email_features.append(0)
            #     else:
            #         email_features.append(0)
            # if len(temp.find_all('link', rel='icon')) == 0:
            #     email_features.append(0)
            # #our dataset so far
            # print("Features for Dataset so Far: ", email_features)

            # # Extract InsecureForms
            # for form in temp.find_all('form'):
            #     action = form.get('action')
            #     if action and not action.startswith("#"):
            #         parsed_url = urlparse(action)
            #         if parsed_url.scheme != "https":
            #             print(f"Insecure form action found: {action}")
            #             email_features.append(1)
            #         else:
            #             print("Insecure form action not found")
            #             email_features.append(0)
            #     else:
            #         email_features.append(0)
            # if len(temp.find_all('form')) == 0:
            #     email_features.append(0)

            # # Extract RelativeFormAction
            # for form in temp.find_all('form'):
            #     action = form.get('action')
            #     if action and not action.startswith("#"):
            #         parsed_url = urlparse(action)
            #         if not parsed_url.scheme and not parsed_url.netloc:
            #             print(f"Relative form action found: {action}")
            #             email_features.append(1)
            #         else:
            #             print("Relative form action not found")
            #             email_features.append(0)
            #     else:
            #         email_features.append(0)
            # if len(temp.find_all('form')) == 0:
            #     email_features.append(0)

            # # Extract ExtFormAction
            # for form in temp.find_all('form'):
            #     action = form.get('action')
            #     if action and not action.startswith("#"):
            #         domain = tldextract.extract(action).domain
            #         if domain != "example" and domain != "localhost":
            #             print(f"External form action found: {action}")
            #             email_features.append(1)
            #         else:
            #             print("External form action not found")
            #             email_features.append(0)
            #     else:
            #         email_features.append(0)
            # if len(temp.find_all('form')) == 0:
            #     email_features.append(0)
            # #our dataset so far
            # print("Features for Dataset so Far: ", email_features)

            # # Extract AbnormalFormAction
            # form_action = "about:blank"
            # if not form_action:
            #     print("Empty form action")
            #     result = 1
            # elif re.search(r"^javascript:true$", form_action):
            #     print("Form action contains javascript:true")
            #     result = 1
            # elif re.search(r"^(#|about:blank)$", form_action):
            #     print("Form action contains # or about:blank")
            #     result = 1
            # else:
            #     print("Normal form action")
            #     result = 0
            # email_features.append(result)

            # # Extract PctNullSelfRedirectHyperlinks
            # total_links = 0
            # null_self_redirect_links = 0
            # for link in temp.find_all('a'):
            #     href = link.get('href')
            #     if href:
            #         total_links += 1
            #         if href == '#' or href == has_link_group_type[i] or href.startswith('file://'):
            #             null_self_redirect_links += 1
            # if total_links > 0:
            #     pct_null_self_redirect_links = null_self_redirect_links / total_links
            #     print(f"Percentage of hyperlinks containing empty value, self-redirect value, or abnormal value: {round(pct_null_self_redirect_links, 2)}")
            #     result = round(pct_null_self_redirect_links, 2)
            # else:
            #     print("No hyperlinks found in HTML")
            #     result = 0
            # email_features.append(result)

            # # Extract FrequentDomainNameMismatch
            # links = [link.get("href") for link in temp.find_all("a") if link.get("href")]
            # url_domain = tldextract.extract(has_link_group_type[i]).domain
            # domains = [tldextract.extract(link).domain for link in links]
            # domain_counts = Counter(domains)
            # most_frequent_domain = domain_counts.most_common(1)[0][0]
            # if most_frequent_domain != url_domain:
            #     result = 1 
            #     print("Frequent domain name mismatch found")
            # else:
            #     result = 0 
            #     print("Frequent domain name mismatch not found")
            # email_features.append(result)

            # # Extract FakeLinkInStatusBar
            # if "onMouseOver" in html_content:
            #     result = 1 
            #     print("Fake link in status bar found")
            # else:
            #     result = 0 
            #     print("Fake link in status bar not found")
            # email_features.append(result)

            # # Extract RightClickDisabled
            # right_click_pattern = re.compile(r'document\.oncontextmenu\s*=\s*function\s*\(\s*\)\s*{\s*return\s+false;\s*}')
            # right_click_disabled = bool(right_click_pattern.search(html_content))
            # if right_click_disabled is True:
            #     result = 1
            #     print("Right_click_disabled: Yes")
            # else:
            #     result = 0
            #     print("Right_click_disabled: No")
            # email_features.append(result)

            # # Extract PopUpWindow
            # if "window.open" in html_content:
            #     result = 1
            #     print("PopUpWindow: Yes")
            # else:
            #     result = 0
            #     print("PopUpWindow: No")
            # email_features.append(result)

            # # Extract SubmitInfoToEmail
            # mailto_links = temp.find_all("a", href=lambda href: href and href.startswith("mailto:"))
            # if mailto_links:
            #     result = 1
            #     print("SubmitInfoToEmail: Yes")
            # else:
            #     result = 0
            #     print("SubmitInfoToEmail: No")
            # email_features.append(result)
            # #our dataset so far
            # print("Features for Dataset so Far: ", email_features)

            # # Extract IframeOrFrame
            # iframes = temp.find_all('iframe')
            # frames = temp.find_all('frame')
            # if iframes or frames:
            #     result = 1
            #     print("Iframe or frame found")
            # else:
            #     result = 0
            #     print("Iframe or frame not found")
            # email_features.append(result)

            # # Extract MissingTitle
            # title = temp.find('title')
            # if title and title.string:
            #     result = 1
            #     print("Title found")
            # else:
            #     result = 0
            #     print("Title not found or empty")
            # email_features.append(result)

            # # Extract ImagesOnlyInForm
            # forms = temp.find_all('form')
            # for form in forms:
            #     if all([img.has_attr('src') for img in form.find_all('img')]) and not form.get_text().strip():
            #         result = 1
            #         print("Images only in form")
            #     else:
            #         result = 0
            #         print("Text found in form")
            # email_features.append(result)

            # # Extract SubdomainLevelRT
            # parsed_url = urlparse(has_link)
            # subdomain_level = parsed_url.hostname.count('.')
            # if subdomain_level == 1:
            #     print("Legitimate")
            #     result = 1
            # elif subdomain_level == 2:
            #     print("Suspicious")
            #     result = 0
            # elif subdomain_level > 2:
            #     print("Phishing")
            #     result = -1
            # email_features.append(result)

            # # Extract UrlLengthRT
            # url_length = len(has_link_group_type[i])
            # if url_length < 54:
            #     print("Legitimate")
            #     result = 1
            # elif url_length >= 54 and url_length <= 75:
            #     print("Suspicious")
            #     result = 0
            # else:
            #     print("Phishing")
            #     result = -1
            # email_features.append(result)

            # # Extract PctExtResourceUrlsRT
            # try:
            #     response = requests.get(has_link_group_type[i], timeout=5)
            #     html = response.text
            # except:
            #     print("Failed to download HTML source code")
            #     result = -1
            # else:
            #     total_resource_urls = 0
            #     external_resource_urls = 0
            #     for tag in temp.find_all(['img', 'link', 'script']):
            #         url = tag.get('src') or tag.get('href')
            #         if url and (url.startswith('http') or url.startswith('//')):
            #             domain = tldextract.extract(url).domain
            #             if domain != tldextract.extract(has_link_group_type[i]).domain:
            #                 external_resource_urls += 1
            #             total_resource_urls += 1
            #     if total_resource_urls > 0:
            #         pct_external_resource_urls = external_resource_urls / total_resource_urls
            #         if pct_external_resource_urls > 10:
            #             result = 1
            #         else:
            #             result = 0
            #         print(f"Percentage of external resource URLs: {round(pct_external_resource_urls, 2)}")
            #     else:
            #         print("No resource URLs found in HTML")
            #         result = -1
            # email_features.append(result)

            # # Extract AbnormalExtFormActionR
            # pattern = re.compile(r'<form.*?\saction=["\'](.*?)["\']', re.IGNORECASE | re.DOTALL)
            # matches = pattern.findall(html_content)
            # for match in matches:
            #     if "http" in match and "://" not in match[:10]:
            #         result = 1
            #         print("Has foreign domain")
            #     elif match.strip() == "about:blank" or not match.strip():
            #         result = 1
            #         print("Has about:blank, or empty string")
            #     else:
            #         result = 0
            #         print("Normal form action attribute")
            # #Possible error around here
            # email_features.append(result)
            # print("Testing 0")
            
            
            # # Extract ExtMetaScriptLinkRT
            # pattern = re.compile(r'(?:meta|script|link).*?\s(?:href|src)=["\'](http.*?)[&"\']', re.IGNORECASE | re.DOTALL)
            # matches = pattern.findall(html_content)
            # meta_count = 0
            # script_count = 0
            # link_count = 0
            
            
            # print("Testing 1")
            
            # for match in matches:
            #     if "http" not in match:
            #         continue
            #     elif "javascript:" in match:
            #         continue
            #     elif match.startswith("#"):
            #         link_count += 1
            #     elif match.startswith("about:blank"):
            #         link_count += 1
            #     elif match.startswith("file://"):
            #         link_count += 1
            #     elif tldextract.extract(match).domain != tldextract.extract(has_link_group_type[i]).domain:
            #         link_count += 1
            #     else:
            #         if "meta" in match:
            #             meta_count += 1
            #         elif "script" in match:
            #             script_count += 1
            #         elif "link" in match:
            #             link_count += 1
            
            # print("Testing 2")
            # total_count = meta_count + script_count + link_count
            # if total_count == 0:
            #     result = 0
            # else:
            #     meta_pct = meta_count / total_count
            #     script_pct = script_count / total_count
            #     link_pct = link_count / total_count
            #     if meta_pct >= 0.5:
            #         result = 1
            #     elif script_pct >= 0.5:
            #         result = 1
            #     elif link_pct >= 0.5:
            #         result = 1
            #     elif link_pct >= 0.1:
            #         result = -1
            #     else:
            #         result = 0
            
            # print("testing 3")
            # email_features.append(result)
            # print("Amount of Metascript: ", result)

            # # Extract PctExtNullSelfRedirectHyperlinksRT
            # pattern = re.compile(r'<a.*?href="(.*?)".*?>')
            # matches = pattern.findall(html_content)
            # external_links = 0
            # null_links = 0
            # self_redirect_links = 0
            
            # print("testing 4")
            # for match in matches:
            #     if match == "" or match.startswith("#") or match.startswith("javascript::void(0)"):
            #         null_links += 1
            #     elif has_link_group_type[i] not in match:
            #         external_links += 1
            #     elif match == has_link_group_type[i] or match == has_link_group_type[i] +"/" or match == has_link_group_type[i] +"#":
            #         self_redirect_links += 1
            # total_links = len(matches)
            # print("testing 5")
            # if total_links == 0:
            #     result = 0
            # print("testing 6")
            # pct_null_links = null_links / total_links
            # pct_external_links = external_links / total_links
            # pct_self_redirect_links = self_redirect_links / total_links
            # print("testing 7")
            # if pct_external_links > 0:
            #     result = 1
            # elif pct_null_links > 0:
            #     result = -1
            # else:
            #     result = 0
            # print("testing 8")
            # email_features.append(result)
            # print("testing 9")
            # print("Amount of  percentage of hyperlinks in HTML source code that uses different domain names: ", result)
            # #our dataset so far
            # print("Features for Dataset so Far: ", email_features)

    #if there are no links, it's unlikely to be phishing (NOTE: 1 is phishing, 0 is not. I'm not keeping in the Class Label)
    # NOT CLASS_LABEL BECAUSE THAT IS WHAT WE ARE PREDICTING
    else:
        email_features = {9820,2,1,2,45,0,0,0,0,0,0,0,0,0,0,
                          1,0,0,0,0,0,22,16,0,0,0,0,0.0583941606,0.1666666667,0,
                          0,0,0,0,0.0291970803,0,0,0,0,0,1,0,0,1,1,
                          1,1,0,1}
    # Combine the extracted features into a numpy array
    
    np.array(email_features)
    print("testing 10")
    print(email_features)

    return email_features

def check_phishing(email_data):
    email_content = email_data.get('email_contents', '')
    if has_zero_links_and_attachments(email_content):
        print("This email has NO links and appears to be safe.")
        return "This email has zero links and zero attachments. It appears to be safe."
    else:
        print("This email contains links. Checking for phishing.")
        #return "This email has links and/ or attachments."
    # Get the currently open email in Outlook
    #email_content = email_data
    print("Part 0")
    # Preprocess the email content
    preprocessed_email_content = preprocess_email_content(email_data)
    print(preprocessed_email_content)

    print("Part 1")

    # Transform the preprocessed email content into a format compatible with the random forest model
    email_features = transform_email_to_features(preprocessed_email_content)
    print("Part 2")
    # RANDOM FOREST ALGORITHM
    # Load and preprocess the dataset
    print("Reading csv file...")
    features = pd.read_csv('src/Phishing_Legitimate_full.csv',sep=',')

    # split the data into label/target and features
    #aka y (THIS SHOULD BE OUR PHISHING/NOT PHISHING COLUMN)
    labels = np.array(features['CLASS_LABEL'])
    #aka x (This should be all of the features)
    features = features.drop('CLASS_LABEL', axis=1)


    print("Part 3")
    #seperate the data into training and testing set
    train_features, test_features, train_labels, test_labels = train_test_split(features, labels, test_size=0.25, random_state=42)
    # Train the RandomForest model classify
    forest = RandomForestClassifier()
    forest.fit(train_features, train_labels)

    # Predict if the email is a phishing attempt using the random forest model
    #possibly change this back to without the reshape
    phishing_prediction = forest.predict([email_features])

    # phishing prediction should output a lost of the features with it's pediction
    # of whether it's phishing or not
    # ex: [0 , 1, 0, 0, 0, 1, 0, 0, 0,..., 0]
    # Set a threshold for the prediction to classify it as phishing or not
    average = stats.mean(phishing_prediction)
    test = str(average)
    phishing_threshold = 0.5
    if average > phishing_threshold:
        print("This email seems legitimate. Prediction: " + test)
        return "This email appears to be authentic and trustworthy. Prediction: " + test
    else:
        print("This email may be a phishing attempt. Prediction: " + test)
        return "This is a phishing attempt. Report this immediately.  Prediction: " + test







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