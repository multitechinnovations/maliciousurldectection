import pandas as pd
from urllib.parse import urlparse as url_parse
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import re
from googlesearch import search
import pickle
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder
from tld import get_tld
import os.path


def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

def abnormal_url(url):
        parsed_url = url_parse(url)
        hostname = parsed_url.hostname
        hostname = str(hostname)
        match = re.search(hostname, url)
        if match:
            return 1
        else:
            return 0
def search_google(url):
    site = search(url, 5)
    return 1 if site else 0

def count_dot(url):
        count_dot = url.count('.')
        return count_dot
    
def count_www(url):
        return url.count('www')

def count_atrate(url):
    return url.count('@')

def no_of_dir(url):
        urldir = url_parse(url).path
        return urldir.count('/')
    
def no_of_embed(url):
        urldir = url_parse(url).path
        return urldir.count('//')

def shortening_service(url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adataset\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                        'tr\.im|link\.zip\.net',
                        url)
        if match:
            return 1
        else:
            return 0
def count_https(url):
        return url.count('https')

def count_http(url):
        return url.count('http')

def count_per(url):
        return url.count('%')
    
def count_ques(url):
        return url.count('?')
    
def count_hyphen(url):
        return url.count('-')

def count_equal(url):
        return url.count('=')
    
def url_length(url):
        return len(str(url))
    
def hostname_length(url):
        return len(url_parse(url).netloc)

def suspicious_words(url):
        match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                        url)
        if match:
            return 1
        else:
            return 0

def digit_count(url):
        digits = 0
        for i in url:
            if i.isnumeric():
                digits = digits + 1
        return digits

def letter_count(url):
        letters = 0
        for i in url:
            if i.isalpha():
                letters = letters + 1
        return letters

def fd_length(url):
        urlpath= url_parse(url).path
        try:
            return len(urlpath.split('/')[1])
        except:
            return 0

def tld_length(tld):
        try:
            return len(tld)
        except:
            return -1
def train_and_save_model():
    print("Dataset:") 
    dataset=pd.read_csv("malicious_phish.csv") 
    print(len(dataset)) 

    dataset_phish = dataset[dataset.type=='phishing']
    dataset_malware = dataset[dataset.type=='malware']
    dataset_deface = dataset[dataset.type=='defacement']
    dataset_benign = dataset[dataset.type=='benign']

  
    dataset['use_of_ip'] = dataset['url'].apply(lambda i: having_ip_address(i))



    dataset['abnormal_url'] = dataset['url'].apply(lambda i: abnormal_url(i))

    dataset['google_index'] = dataset['url'].apply(lambda i: search_google(i))


    dataset['count.'] = dataset['url'].apply(lambda i: count_dot(i))
    

    dataset['count-www'] = dataset['url'].apply(lambda i: count_www(i))


    dataset['count@'] = dataset['url'].apply(lambda i: count_atrate(i))


    dataset['count_dir'] = dataset['url'].apply(lambda i: no_of_dir(i))


    dataset['count_embed_domian'] = dataset['url'].apply(lambda i: no_of_embed(i))

    dataset['short_url'] = dataset['url'].apply(lambda i: shortening_service(i))


    dataset['count-https'] = dataset['url'].apply(lambda i: count_https(i))


    dataset['count-http'] = dataset['url'].apply(lambda i: count_http(i))


    dataset['count%'] = dataset['url'].apply(lambda i: count_per(i))


    dataset['count?'] = dataset['url'].apply(lambda i: count_ques(i))


    dataset['count-'] = dataset['url'].apply(lambda i: count_hyphen(i))


    dataset['count='] = dataset['url'].apply(lambda i: count_equal(i))


    dataset['url_length'] = dataset['url'].apply(lambda i: url_length(i))


    dataset['hostname_length'] = dataset['url'].apply(lambda i: hostname_length(i))


    dataset['sus_url'] = dataset['url'].apply(lambda i: suspicious_words(i))


    dataset['count-digits']= dataset['url'].apply(lambda i: digit_count(i))



    dataset['count-letters']= dataset['url'].apply(lambda i: letter_count(i))



    dataset['fd_length'] = dataset['url'].apply(lambda i: fd_length(i))

    dataset['tld'] = dataset['url'].apply(lambda i: get_tld(i,fail_silently=True))



    dataset['tld_length'] = dataset['tld'].apply(lambda i: tld_length(i))

    print(dataset.columns,len(dataset.columns))
    dataset.dropna(inplace=True)
    # split dataset 
    x = dataset[['use_of_ip','abnormal_url', 'count.', 'count-www', 'count@',
        'count_dir', 'count_embed_domian', 'short_url', 'count-https',
        'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
        'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits',
        'count-letters']]
    y = dataset["type"] 
    x_train, x_test, y_train, y_test = train_test_split(x, y, stratify=y, test_size=0.2,shuffle=True, random_state=5)

    # Feature Scaling 
    sc_x=StandardScaler() 
    x_train=sc_x.fit_transform(x_train) 
    x_test=sc_x.transform(x_test) 

    import math 
    a=math.sqrt(len(y_train)) 
    print(a) 

    label_encoder = LabelEncoder()

    y_train_encoded = label_encoder.fit_transform(y_train)
    y_test_encoded = label_encoder.transform(y_test)

    c = xgb.XGBClassifier(n_estimators=100)
    c.fit(x_train, y_train_encoded)

    with open("model.pkl", "wb") as model_file:
        pickle.dump(c, model_file)

    with open("scaler.pkl", "wb") as scaler_file:
        pickle.dump(sc_x, scaler_file)

    with open("label_encoder.pkl", "wb") as label_encoder_file:
        pickle.dump(label_encoder, label_encoder_file)


def preprocess_url(url):
    # Extract features from the URL
    use_of_ip = having_ip_address(url)
    abnormal = abnormal_url(url)
    google_index = search_google(url)
    count_dot_value = count_dot(url)
    count_www_value = count_www(url)
    count_at_value = count_atrate(url)
    count_dir_value = no_of_dir(url)
    count_embed_domain_value = no_of_embed(url)
    short_url_value = shortening_service(url)
    count_https_value = count_https(url)
    count_http_value = count_http(url)
    count_percent_value = count_per(url)
    count_question_value = count_ques(url)
    count_hyphen_value = count_hyphen(url)
    count_equal_value = count_equal(url)
    url_length_value = len(url)
    hostname_length_value = len(url_parse(url).netloc)
    suspicious_url_value = suspicious_words(url)
    digit_count_value = digit_count(url)
    letter_count_value = letter_count(url)
    first_dir_length_value = fd_length(url)
    top_level_domain_length_value = tld_length(get_tld(url, fail_silently=True))

    # Add other features as needed

    # Return a list of numerical features
    return [use_of_ip, abnormal, count_dot_value, count_www_value, count_at_value,
            count_dir_value, count_embed_domain_value, short_url_value, count_https_value, count_http_value,
            count_percent_value, count_question_value, count_hyphen_value, count_equal_value, url_length_value,
            hostname_length_value, suspicious_url_value, first_dir_length_value, top_level_domain_length_value,
            digit_count_value, letter_count_value]
