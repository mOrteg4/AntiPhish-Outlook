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

        # Extract IpAddress

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
        double_slash_in_path = path.count("\\")
        email_features.append(double_slash_in_path)
        # Extract NumSensitiveWords
        # Extract EmbeddedBrandName
        # Extract PctExtHyperlinks (Counts the percentage of external hyperlinks in webpage HTML source code)
        # Extract PctExtResourceUrls
        # Extract ExtFavicon
        # Extract InsecureForms
        # Extract RelativeFormAction
        # Extract ExtFormAction
        # Extract AbnormalFormAction
        # Extract PctNullSelfRedirectHyperlinks
        # Extract FrequentDomainNameMismatch
        # Extract FakeLinkInStatusBar
        # Extract RightClickDisabled
        # Extract PopUpWindow
        # Extarct SubmitInfoToEmail
        # Extract IframeOrFrame
        # Extract MissingTitle
        # Extract ImagesOnlyInForm
        # Extract SubdomainLevelRT
        # Extract UrlLengthRT
        # Extract PctExtResourceUrlsRT
        # Extract AbnormalExtFormActionR
        # Extract ExtMetaScriptLinkRT
        # Extract PctExtNullSelfRedirectHyperlinksRT
        # Extract CLASS_LABEL

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