import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.tree import export_graphviz
import pydot
import re
import tldextract
import urlparse
import win32com.client
import requests
from bs4 import BeautifulSoup
from collections import Counter
import sys


def preprocess_email_content(email_content):
    preprocessed_content = email_content.lower()
    return preprocessed_content

def get_current_email():
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
        '''UNSURE ABOUT THIS, might need to return in binary'''
        pattern = r"[a-z0-9]{8,}"
        matches = re.findall(pattern, has_link)
        if matches:
            # result = b"\x01"
            result = "Random string found"
        else:
            # result = b"\x00"
            result = "Random string not found"
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
        '''UNSURE ABOUT THIS, might need to return in binary'''
        domain_names = [urlparse(link.get("href")).hostname for link in temp.find_all("a") if link.get("href")]
        domain_name_counts = Counter(domain_names)
        most_frequent_domain_name = domain_name_counts.most_common(1)[0][0]
        parsed_url = urlparse(has_link)
        subdomains = parsed_url.hostname.split(".")[:-2]
        path = parsed_url.path
        if most_frequent_domain_name in subdomains or most_frequent_domain_name in path:
            # result = b"\x01"
            result = "Brand name embedded"
        else:
            # result = b"\x00"
            result = "Brand name not embedded"
        email_features.append(result)
        # Extract PctExtHyperlinks (Counts the percentage of external hyperlinks in webpage HTML source code)
        # Extract PctExtResourceUrls
        # Extract ExtFavicon
        # Extract InsecureForms
        # Extract RelativeFormAction
        # Extract ExtFormAction
        # Extract AbnormalFormAction
        # Extract PctNullSelfRedirectHyperlinks
        '''UNSURE ABOUT THIS, might need to return in binary'''
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
            # result = b"\x01" 
            result = "Suspicious percentage of null or self-redirect hyperlinks"
        else:
            # result = b"\x00" 
            result = "Normal percentage of null or self-redirect hyperlinks"
        # Extract FrequentDomainNameMismatch
        '''UNSURE ABOUT THIS, might need to return in binary'''
        links = [link.get("href") for link in temp.find_all("a")]
        url_domain = tldextract.extract(has_link).domain
        domains = [tldextract.extract(link).domain for link in links]
        domain_counts = Counter(domains)
        most_frequent_domain = domain_counts.most_common(1)[0][0]
        if most_frequent_domain != url_domain:
            # result = b"\x01" 
            result = "Frequent domain name mismatch found"
        else:
            # result = b"\x00" 
            result = "Frequent domain name mismatch not found"
        email_features.append(result)
        # Extract FakeLinkInStatusBar
        '''UNSURE ABOUT THIS, might need to return in binary'''
        if "onMouseOver" in html_content:
            # result = b"\x01" 
            result = "Fake link in status bar found"
        else:
            # result = b"\x00" 
            result = "Fake link in status bar not found"
        email_features.append(result)
        # Extract RightClickDisabled
        '''UNSURE ABOUT THIS, might need to return in binary'''
        right_click_pattern = re.compile(r'document\.oncontextmenu\s*=\s*function\s*\(\s*\)\s*{\s*return\s+false;\s*}')
        right_click_disabled = bool(right_click_pattern.search(html_content))
        if right_click_disabled is True:
            # result = b"\x01"
            result = "Right_click_disabled: Yes"
        else:
            # result = b"\x00"
            result = "Right_click_disabled: No"
        email_features.append(result)
        # Extract PopUpWindow
        '''UNSURE ABOUT THIS, might need to return in binary'''
        if "window.open" in html_content:
            # result = b"\x01"
            result = "PopUpWindow: Yes"
        else:
            # result = b"\x00"
            result = "PopUpWindow: No"
        email_features.append(result)
        # Extract SubmitInfoToEmail
        '''UNSURE ABOUT THIS, might need to return in binary'''
        mailto_links = temp.find_all("a", href=lambda href: href and href.startswith("mailto:"))
        if mailto_links:
            # result = b"\x01"
            result = "SubmitInfoToEmail: Yes"
        else:
            # result = b"\x00"
            result = "SubmitInfoToEmail: No"
        email_features.append(result)
        # Extract IframeOrFrame
        '''UNSURE ABOUT THIS, might need to return in binary'''
        iframes = temp.find_all('iframe')
        frames = temp.find_all('frame')
        if iframes or frames:
            # result = b"\x01"
            result = "Iframe or frame found"
        else:
            # result = b"\x00"
            result = "Iframe or frame not found"
        email_features.append(result)
        # Extract MissingTitle
        '''UNSURE ABOUT THIS, might need to return in binary'''
        title = temp.find('title')
        if title and title.string:
            # result = b"\x01"
            result = "Title found"
        else:
            # result = b"\x00"
            result = "Title not found or empty"
        email_features.append(result)
        # Extract ImagesOnlyInForm
        '''UNSURE ABOUT THIS, might need to return in binary'''
        forms = temp.find_all('form')
        for form in forms:
            if all([img.has_attr('src') for img in form.find_all('img')]) and not form.get_text().strip():
                # result = b"\x01"
                result = "Images only in form"
            else:
                # result = b"\x00"
                result = "Text found in form"
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
        '''UNSURE ABOUT THIS, might need to return in binary'''
        pattern = re.compile(r'<form.*?\saction=["\'](.*?)["\']', re.IGNORECASE | re.DOTALL)
        matches = pattern.findall(html_content)
        for match in matches:
            # check for foreign domain
            if "http" in match and "://" not in match[:10]:
                # result = b"\x01"
                result = "Has foreign domain"
            # check for about:blank or empty string
            elif match.strip() == "about:blank" or not match.strip():
                # result = b"\x01"
                result = "Has about:blank, or empty string"
            else:
                # result = b"\x00"
                result = "Normal form action attribute"
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
                # check if the link has a different domain name
                if parsed_href.netloc != urlparse(temp.base.get('href')).netloc:
                    ext_links += 1
                elif parsed_href.path.startswith('#'):
                    # check if the link starts with "#"
                    self_redirect_links += 1
                elif parsed_href.path.startswith('JavaScript::'):
                    # check if the link uses "JavaScript:: void(0)"
                    self_redirect_links += 1
        # calculate the percentage of links with different domain names, "#", or "JavaScript:: void(0)"
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
features = pd.read_csv('Phishing_Legitimate_full.csv')
features = pd.get_dummies(features)

labels = np.array(features['id'])
features = features.drop('id', axis=1)
feature_list = list(features.columns)
features = np.array(features)

#seperate the data into training and testing set
train_features, test_features, train_labels, test_labels = train_test_split(features, labels, test_size=0.25, random_state=42)
# Train the RandomForest model
rf = RandomForestRegressor(n_estimators=1000, random_state=42)
rf.fit(train_features, train_labels)

# Get the currently open email in Outlook
email_content = "what"#get_current_email()

# Preprocess the email content
preprocessed_email_content = preprocess_email_content(email_content)

# Transform the preprocessed email content into a format compatible with the random forest model
email_features = transform_email_to_features(preprocessed_email_content)

# Predict if the email is a phishing attempt using the random forest model
#possibly change this back to without the reshape
phishing_prediction = rf.predict(email_features.reshape(1, -1))

# Set a threshold for the prediction to classify it as phishing or not
phishing_threshold = 0.5
if phishing_prediction > phishing_threshold:
    print("This email may be a phishing attempt.")
else:
    print("This email seems legitimate.")

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