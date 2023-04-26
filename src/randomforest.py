import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.tree import export_graphviz
import pydot
import re
import tldextract
from urllib.parse import urlparse
import win32com.client
import requests
from bs4 import BeautifulSoup
from collections import Counter
import sys

def check_phishing(email_data):
    print(email_data)
    return "This is a phishing attempt. Report this immediately"

def preprocess_email_content(email_content):
    print("Preprocessing email contents...")
    preprocessed_content = email_content.lower()
    return preprocessed_content

def get_current_email():
    print("Getting current email...")
    outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
    explorer = outlook.Application.ActiveExplorer()
    selection = explorer.Selection
    if len(selection) == 1:
        email = selection.Item(1)
        return email.Subject + " " + email.Body
    else:
        raise Exception("No email is currently open or more than one email is selected.")

# Add transform_email_to_features function here
def transform_email_to_features(preprocessed_email_content):
    # Initialize a list to store the extracted features
    email_features = []

    #check if there are links
    link = re.compile('<a[^>]+href=\'(.*?)\'[^>]*>(.*)?</a>')
    has_link = link.search(preprocess_email_content)
    # GET request to URL
    response = requests.get(has_link)
    # pasrse HTML content
    temp = BeautifulSoup(response.content, 'html.parser')
    html_content = response.text
    #if there are links, get data to check if phishing (im assuming theres one link for now)
    if has_link is not None:
        # Extract ID
        email_features.append(re.findall('\d+',has_link))
        # Extract NumDots from preprocessed_email_content
        num_dots = has_link.count(".")
        email_features.append(num_dots)
        # Extract SubdomainLevel
        ext = tldextract.extract(has_link) #https://pypi.org/project/tldextract/
        sub = ext.subdomain
        sub.split('.')
        email_features.append(sub.size)
        # Extract PathLevel
        path = urlparse.urlparse(has_link)
        path.split('/')
        email_features.append(len(path))
        # Extract UrlLength
        email_features.append(len(has_link))
        # Extract NumDash from preprocessed_email_content
        num_dash = has_link.count("-")
        email_features.append(num_dash)
        # Extract NumDashInHostname
        ext = tldextract.extract(has_link)
        domain = ext.domain
        num_dash_in_domain = domain.count("/")
        email_features.append(num_dash_in_domain)
        # Extract AtSymbol
        at_symbol = has_link.count("@")
        email_features.append(at_symbol)
        # Extract TildeSymbol
        tilde_symbol = has_link.count("~")
        email_features.append(tilde_symbol)
        # Extract NumUnderscore from preprocessed_email_content
        num_underscore = has_link.count("_")
        email_features.append(num_underscore)
        # Extract NumPercent from preprocessed_email_content
        num_percent = has_link.count("%")
        email_features.append(num_percent)
        #Extract NumQueryComponents
        num_query_components = has_link.count("?")
        email_features.append(num_query_components)
        # Extract NumAmpersand from preprocessed_email_content
        num_ampersand = has_link.count("&")
        email_features.append(num_ampersand)
        # Extract NumHash from preprocessed_email_content
        num_hash = has_link.count("#")
        email_features.append(num_hash)
        # Extract NumNumericChars from preprocessed_email_content
        num_numeric_chars = sum(c.isdigit() for c in has_link)
        email_features.append(num_numeric_chars)
        # Extract NoHttps
        https = has_link.count("https")
        email_features.append(https)
        # Extract RandomString
        pattern = r"[a-z0-9]{8,}"
        matches = re.findall(pattern, has_link)
        if matches:
            result = b"\x01"
            print("Random string found")
        else:
            result = b"\x00"
            print("Random string not found")
        email_features.append(result)
        # Extract IpAddress
        header = preprocess_email_content.get('Received')
        ip_address = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', header).group(0)
        email_features.append(ip_address)
        # Extract DomainInSubdomains
        ext = tldextract.extract(has_link)
        sub = ext.sub
        domain = ext.domain
        domain_in_sub = sub.count(domain)
        email_features.append(domain_in_sub)
        # Extract DomainInPaths
        path = urlparse.urlparse(has_link)
        ext = tldextract.extract(has_link)
        domain = ext.domain
        domain_in_path = path.count(domain)
        email_features.append(domain_in_path)
        # Extract HttpsInHostname
        ext = tldextract.extract(has_link)
        domain = ext.domain
        https_in_domain = domain.count("https")
        email_features.append(https_in_domain)
        # Extract HostnameLength
        ext = tldextract.extract(has_link)
        domain = ext.domain
        email_features.append(len(domain))
        # Extract PathLength
        path = urlparse.urlparse(has_link)
        email_features.append(len(path))
        # Extract QueryLength
        queries = has_link.split("?")
        query_length = 0
        for i in queries[1:]:
            query_length = query_length + len(queries[i])
        email_features.append(query_length)
        # Extract DoubleSlashInPath
        path = urlparse.urlparse(has_link)
        double_slash_in_path = path.count("//")
        email_features.append(double_slash_in_path)
        # Extract NumSensitiveWords
        sensitive_words = ["secure", "account", "webscr", "login", "ebayisapi", "signin", "banking", "confirm"]
        num_sensitive_words = sum([1 for word in sensitive_words if re.search(word, has_link, re.IGNORECASE)])
        email_features.append(num_sensitive_words)
        # Extract EmbeddedBrandName
        domain_names = [urlparse(link.get("href")).hostname for link in temp.find_all("a") if link.get("href")]
        domain_name_counts = Counter(domain_names)
        most_frequent_domain_name = domain_name_counts.most_common(1)[0][0]
        parsed_url = urlparse(has_link)
        subdomains = parsed_url.hostname.split(".")[:-2]
        path = parsed_url.path
        if most_frequent_domain_name in subdomains or most_frequent_domain_name in path:
            result = b"\x01"
            print("Brand name embedded")
        else:
            result = b"\x00"
            print("Brand name not embedded")
        email_features.append(result)
        # Extract PctExtHyperlinks (Counts the percentage of external hyperlinks in webpage HTML source code)
        total_links = 0
        external_links = 0
        for link in temp.find_all('a'):
            href = link.get('href')
            if href and (href.startswith('http') or href.startswith('//')):
                domain = tldextract.extract(href).domain
                if domain != tldextract.extract(has_link).domain:
                    external_links += 1
                total_links += 1
        if total_links > 0:
            pct_external_links = (external_links / total_links) * 100
            print(f"Percentage of external hyperlinks: {pct_external_links:.2f}%")
            result = f"{pct_external_links:.2f}%"
        else:
            print("No hyperlinks found in HTML")
            result = "0%"
        email_features.append(result)
        # Extract PctExtResourceUrls
        total_resources = 0
        external_resources = 0
        for tag in temp.find_all():
            if tag.has_attr('href'):
                href = tag['href']
                if href.startswith('http') or href.startswith('//'):
                    domain = tldextract.extract(href).domain
                    if domain != tldextract.extract(has_link).domain:
                        external_resources += 1
                total_resources += 1
            if tag.has_attr('src'):
                src = tag['src']
                if src.startswith('http') or src.startswith('//'):
                    domain = tldextract.extract(src).domain
                    if domain != tldextract.extract(has_link).domain:
                        external_resources += 1
                total_resources += 1
        if total_resources > 0:
            pct_external_resources = (external_resources / total_resources) * 100
            print(f"Percentage of external resource URLs: {pct_external_resources:.2f}%")
            result = f"{pct_external_resources:.2f}%"
        else:
            print("No resource URLs found in HTML")
            result = "0%"
        email_features.append(result)
        # Extract ExtFavicon
        for link in temp.find_all('link', rel='icon'):
            href = link.get('href')
            if href:
                domain = tldextract.extract(href).domain
                if domain != tldextract.extract(has_link).domain:
                    print(f"External favicon found: {href}")
                    result = b"\x01"
                else:
                    print("External favicon not found")
                    result = b"\x00"
        email_features.append(result)
        # Extract InsecureForms
        for form in temp.find_all('form'):
            action = form.get('action')
            if action and not action.startswith("#"):
                parsed_url = urlparse(action)
                if parsed_url.scheme != "https":
                    print(f"Insecure form action found: {action}")
                    result = b"\x01"
                else:
                    print("Insecure form action not found")
                    result = b"\x00"
        email_features.append(result)
        # Extract RelativeFormAction
        for form in temp.find_all('form'):
            action = form.get('action')
            if action and not action.startswith("#"):
                parsed_url = urlparse(action)
                if not parsed_url.scheme and not parsed_url.netloc:
                    print(f"Relative form action found: {action}")
                    result = b"\x01"
                else:
                    print("Relative form action not found")
                    result = b"\x00"
        email_features.append(result)
        # Extract ExtFormAction
        for form in temp.find_all('form'):
            action = form.get('action')
            if action and not action.startswith("#"):
                domain = tldextract.extract(action).domain
                if domain != "example" and domain != "localhost":
                    print(f"External form action found: {action}")
                    result = b"\x01"
                else:
                    print("External form action not found:")
                    result = b"\x00"
        email_features.append(result)
        # Extract AbnormalFormAction
        for form in temp.find_all('form'):
            action = form.get('action')
            if "#" in action or action == "about:blank" or action == "" or action == "javascript:true":
                print(f"Abnormal form action found: {action}")
                email_features.append(action)
        # Extract PctNullSelfRedirectHyperlinks
        hyperlinks = [link.get("href") for link in temp.find_all("a")]
        num_null_hyperlinks = 0
        num_self_redirect_hyperlinks = 0
        num_abnormal_hyperlinks = 0
        for link in hyperlinks:
            if link is None or link == "":
                num_null_hyperlinks += 1
            elif link == "#" or link == has_link or link.startswith("file://"):
                num_self_redirect_hyperlinks += 1
            else:
                num_abnormal_hyperlinks += 1
        total_hyperlinks = len(hyperlinks)
        pct_null_hyperlinks = num_null_hyperlinks / total_hyperlinks * 100
        pct_self_redirect_hyperlinks = num_self_redirect_hyperlinks / total_hyperlinks * 100
        pct_abnormal_hyperlinks = num_abnormal_hyperlinks / total_hyperlinks * 100
        pct_null_self_redirect_hyperlinks = pct_null_hyperlinks + pct_self_redirect_hyperlinks + pct_abnormal_hyperlinks
        if pct_null_self_redirect_hyperlinks > 20:
            result = b"\x01" 
            print("Suspicious percentage of null or self-redirect hyperlinks")
        else:
            result = b"\x00" 
            print("Normal percentage of null or self-redirect hyperlinks")
        # Extract FrequentDomainNameMismatch
        links = [link.get("href") for link in temp.find_all("a")]
        url_domain = tldextract.extract(has_link).domain
        domains = [tldextract.extract(link).domain for link in links]
        domain_counts = Counter(domains)
        most_frequent_domain = domain_counts.most_common(1)[0][0]
        if most_frequent_domain != url_domain:
            result = b"\x01" 
            print("Frequent domain name mismatch found")
        else:
            result = b"\x00" 
            print("Frequent domain name mismatch not found")
        email_features.append(result)
        # Extract FakeLinkInStatusBar
        if "onMouseOver" in html_content:
            result = b"\x01" 
            print("Fake link in status bar found")
        else:
            result = b"\x00" 
            print("Fake link in status bar not found")
        email_features.append(result)
        # Extract RightClickDisabled
        right_click_pattern = re.compile(r'document\.oncontextmenu\s*=\s*function\s*\(\s*\)\s*{\s*return\s+false;\s*}')
        right_click_disabled = bool(right_click_pattern.search(html_content))
        if right_click_disabled is True:
            result = b"\x01"
            print("Right_click_disabled: Yes")
        else:
            result = b"\x00"
            print("Right_click_disabled: No")
        email_features.append(result)
        # Extract PopUpWindow
        if "window.open" in html_content:
            result = b"\x01"
            print("PopUpWindow: Yes")
        else:
            result = b"\x00"
            print("PopUpWindow: No")
        email_features.append(result)
        # Extract SubmitInfoToEmail
        mailto_links = temp.find_all("a", href=lambda href: href and href.startswith("mailto:"))
        if mailto_links:
            result = b"\x01"
            print("SubmitInfoToEmail: Yes")
        else:
            result = b"\x00"
            print("SubmitInfoToEmail: No")
        email_features.append(result)
        # Extract IframeOrFrame
        iframes = temp.find_all('iframe')
        frames = temp.find_all('frame')
        if iframes or frames:
            result = b"\x01"
            print("Iframe or frame found")
        else:
            result = b"\x00"
            print("Iframe or frame not found")
        email_features.append(result)
        # Extract MissingTitle
        title = temp.find('title')
        if title and title.string:
            result = b"\x01"
            print("Title found")
        else:
            result = b"\x00"
            print("Title not found or empty")
        email_features.append(result)
        # Extract ImagesOnlyInForm
        forms = temp.find_all('form')
        for form in forms:
            if all([img.has_attr('src') for img in form.find_all('img')]) and not form.get_text().strip():
                result = b"\x01"
                print("Images only in form")
            else:
                result = b"\x00"
                print("Text found in form")
        email_features.append(result)
        # Extract SubdomainLevelRT
        subdomain_level = has_link.hostname.count('.')
        if subdomain_level == 1:
            result = "Legitimate"
        elif subdomain_level == 2:
            result = "Suspicious"
        elif subdomain_level > 2:
            result = "Phishing"
        email_features.append(result)
        # Extract UrlLengthRT
        url_length = len(has_link)
        if url_length < 54:
            result = "Legitimate"
        elif url_length >= 54 and url_length <= 75:
            result = "Suspicious"
        else:
            result = "Phishing"
        email_features.append(result)
        # Extract PctExtResourceUrlsRT
        '''UNSURE ABOUT THIS'''
        total_urls = 0
        external_urls = 0
        for tag in temp.find_all():
            for attr in tag.attrs.values():
                if isinstance(attr, str):
                    if attr.startswith('http') or attr.startswith('//'):
                        total_urls += 1
                        if not has_link in attr:
                            external_urls += 1
        if total_urls > 0:
            pct_external_urls = (external_urls / total_urls) * 100
        else:
            pct_external_urls = 0
        email_features.append(pct_external_urls)
        # Extract AbnormalExtFormActionR
        pattern = re.compile(r'<form.*?\saction=["\'](.*?)["\']', re.IGNORECASE | re.DOTALL)
        matches = pattern.findall(html_content)
        for match in matches:
            if "http" in match and "://" not in match[:10]:
                result = b"\x01"
                print("Has foreign domain")
            elif match.strip() == "about:blank" or not match.strip():
                result = b"\x01"
                print("Has about:blank, or empty string")
            else:
                result = b"\x00"
                print("Normal form action attribute")
        email_features.append(result)
        # Extract ExtMetaScriptLinkRT
        pattern = re.compile(r'(?:meta|script|link).*?\s(?:href|src)=["\'](http.*?)[&"\']', re.IGNORECASE | re.DOTALL)
        matches = pattern.findall(html_content)
        meta_count = 0
        script_count = 0
        for match in matches:
            if "meta" in match:
                meta_count += 1
            elif "script" in match:
                script_count += 1
            elif "link" in match:
                link_count += 1
        total_count = meta_count + script_count + link_count
        if total_count == 0:
            return 0, 0, 0
        else:
            meta_pct = meta_count / total_count
            script_pct = script_count / total_count
            link_pct = link_count / total_count
        email_features.append(meta_pct, script_pct, link_pct)
        # Extract PctExtNullSelfRedirectHyperlinksRT
        total_links = 0
        ext_links = 0
        null_links = 0
        self_redirect_links = 0
        for link in temp.find_all('a'):
            total_links += 1
            href = link.get('href')
            if not href:
                null_links += 1
                continue
            parsed_href = urlparse(href)
            if parsed_href.scheme and parsed_href.netloc:
                if parsed_href.netloc != urlparse(temp.base.get('href')).netloc:
                    ext_links += 1
                elif parsed_href.path.startswith('#'):
                    self_redirect_links += 1
                elif parsed_href.path.startswith('JavaScript::'):
                    self_redirect_links += 1
        if total_links > 0:
            pct_ext_links = ext_links / total_links * 100
            pct_null_links = null_links / total_links * 100
            pct_self_redirect_links = self_redirect_links / total_links * 100
        elif total_count == 0:
            return 0, 0, 0
        email_features.append(pct_ext_links, pct_null_links, pct_self_redirect_links)
            # Extract CLASS_LABEL
            ### NO IDEA ####

    #if there are no links, it's unlikely to be phishing
    else:
        email_features = {1,3,1,5,72,0,0,0,0,0,0,0,0,0,0,1,
                          0,0,0,0,0,21,44,0,0,0,0,0,0.25,1,1,
                          0,0,0,0,0,0,0,0,0,0,0,1,1,0,1,1,-1,1,1}
    # Combine the extracted features into a numpy array
    email_features = np.array(email_features)

    return email_features



# Load and preprocess the dataset
print("Reading csv file...")
features = pd.read_csv('Phishing_Legitimate_full.csv')
features = pd.get_dummies(features)

print("Settings labels & features...")
labels = np.array(features['id'])
features = features.drop('id', axis=1)
feature_list = list(features.columns)
features = np.array(features)

#seperate the data into training and testing set
print("Seperating the data into training and testing set...")
train_features, test_features, train_labels, test_labels = train_test_split(features, labels, test_size=0.25, random_state=42)
# Train the RandomForest model
print("Training the RandomForest model...")
rf = RandomForestRegressor(n_estimators=1000, random_state=42)
rf.fit(train_features, train_labels)

# Get the currently open email in Outlook
#email_content = "what"#get_current_email()

# Preprocess the email content
#preprocessed_email_content = preprocess_email_content(email_content)

# Transform the preprocessed email content into a format compatible with the random forest model
#email_features = transform_email_to_features(preprocessed_email_content)

# Predict if the email is a phishing attempt using the random forest model
#possibly change this back to without the reshape
#phishing_prediction = rf.predict(email_features.reshape(1, -1))

# Set a threshold for the prediction to classify it as phishing or not
#phishing_threshold = 0.5
#if phishing_prediction > phishing_threshold:
    #print("This email may be a phishing attempt.")
#else:
    #print("This email seems legitimate.")

# Everything under here is to help us fix the model, so I commented it out since we dont need it anymore
# Visualize the RandomForest 
#tree = rf.estimators_[5]
#export_graphviz(tree, out_file='tree.dot', feature_names=feature_list, rounded=True, precision=1)
#(graph,) = pydot.graph_from_dot_file('tree.dot')
#graph.write_png('tree.png')

# Limit depth of tree to 3 levels
#rf_small = RandomForestRegressor(n_estimators=10, max_depth=3)
#rf_small.fit(train_features, train_labels)
#tree_small = rf_small.estimators_[5]
#export_graphviz(tree_small, out_file='small_tree.dot', feature_names=feature_list, rounded=True, precision=1)
#(graph,) = pydot.graph_from_dot_file('small_tree.dot')
#graph.write_png('small_tree.png')