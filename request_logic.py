import os.path,requests,json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64
from proto import client_pb2
import json
import logging
import entry_decoder
from google.protobuf.json_format import MessageToJson


def _parse_sth(sth_body):
    """Parse a serialized STH JSON response."""
    sth_response = client_pb2.SthResponse()
    try:
        sth = json.loads(sth_body)
        sth_response.timestamp = int(sth["timestamp"])
        sth_response.tree_size = int(sth["tree_size"])
        sth_response.sha256_root_hash = base64.b64decode(sth[
            "sha256_root_hash"])
        sth_response.tree_head_signature = base64.b64decode(sth[
            "tree_head_signature"])
        # TypeError for base64 decoding, TypeError/ValueError for invalid
        # JSON field types, KeyError for missing JSON fields.
    except (TypeError, ValueError, KeyError) as error:
        print(error)
        raise
    return sth_response


def _parse_entry(json_entry):
    """Convert a json array element to an EntryResponse."""
    entry_response = client_pb2.EntryResponse()
    try:
        entry_response.leaf_input = base64.b64decode(
            json_entry["leaf_input"])
        entry_response.extra_data = base64.b64decode(
            json_entry["extra_data"])
    except (TypeError, ValueError, KeyError) as error:
        print(error)
        raise
    return entry_response


def _parse_entries(entries_body):
    """Load serialized JSON response.
    Args:
        entries_body: received entries.
        expected_response_size: number of entries requested. Used to validate
            the response.
    Returns:
        a list of client_pb2.EntryResponse entries.
    Raises:
        InvalidResponseError: response not valid.
    """
    try:
        response = json.loads(entries_body)
    except (TypeError, ValueError, KeyError) as error:
        print(error)
        raise
    try:
        entries = iter(response["entries"])
    except (TypeError, ValueError, KeyError) as error:
        print(error)
        raise
    return [_parse_entry(e) for e in entries]

def get_entries(url, start, end):
    get_entries_url = url + 'ct/v1/get-entries'
    print("Getting entries %d to %d from %s" % (start,end,url))
    params = {'start':start, 'end':end}
    #data = requests.request("get",get_entries_url, params=params)
    data = requests.get(get_entries_url, params=params)
    if data.status_code == 200:
        print ('Success')
        return(data.content)
    else:
        print("Error getting entries.\n Status code: %s" % (data.status_code))

def get_all_entries(url):
    get_sth_url = url + 'ct/v1/get-sth'
    print("Getting range from %s" % (url))
    data = requests.request("get",get_sth_url)
    if data.status_code == 200:
        p_data = data.json()
        start = 0
        batch_end = 0
        end = (p_data['tree_size']) - 1
        while batch_end < end:
            batch_end = start + 256
            get_entries(url,start,batch_end)
            start = start + 256
    else:
        print("Error getting entries.\n Status code: %s" % (data.status_code))

def write_currentSTH(sth):
    file = open("current_sth.json","w")
    #print(sth.SerializeToString())
    file.write(MessageToJson(sth, preserving_proto_field_name=True))
    file.close

def read_currentSTH():
    #Get current STH from file
    file = open("current_sth.json","r")
    data = file.read()
    #print(data)
    current_sth = _parse_sth(data)
    file.close
    return current_sth

def get_sth_from_log(url):
    #Get new STH from URL
    get_sth_url = url + 'ct/v1/get-sth'
    #sth = ct_pb2.SignedTreeHead()
    print("Getting STH from %s" % (url))
    data = requests.request("get",get_sth_url)
    if data.status_code == 200:
        new_sth = _parse_sth(data.content)
        #print(new_sth)
        return new_sth
    else:
        print("Error getting entries.\n Status code: %s" % (data.status_code))
        return None

def init_Log_Monitor(url):
    print("Getting initial Signed Tree Head")
    write_currentSTH(get_sth_from_log(url))

def check_for_match(cert_subject):
    result = ""
    if os.path.isfile("domains.conf"):
        domains = [line.rstrip('\n') for line in open('domains.conf')]
        for domain in domains:
            if domain in cert_subject:
                print(domain)
                result += domain
    else:
        print("Can't find domains to check against.")
    return result

def check_for_new_sth(url):
    current_sth = read_currentSTH()
    new_sth = get_sth_from_log(url)
    #Compare the two STH's hash.
    #If they are equal we don't have to do anything.
    #If they are different there are new entries in the logs we have to check.
    #if current_sth['sha256_root_hash'] == new_sth['sha256_root_hash']:
    if current_sth.sha256_root_hash == new_sth.sha256_root_hash:
    #DEBUG
    #if current_sth.tree_head_signature != current_sth.tree_head_signature:
        print("No new STH found. Going back to sleep.")
    else:
        print("New STH found!")
        #entries = get_entries(url,current_sth['tree_size'],new_sth['tree_size'])
        entries = get_entries(url,567318792,567318792)
        p_entries=(_parse_entries(entries))
        #print(p_entries)
        #heavily inspired by https://github.com/google/certificate-transparency/blob/master/python/ct/client/monitor.py#L295
        for entry in p_entries:
            d_entry = entry_decoder.decode_entry(entry)
            ts_entry = d_entry.merkle_leaf.timestamped_entry
            #Below shows Leaf Structure (for blog)
            #print(d_entry.merkle_leaf)
            #If the entry includes a certificate
            if ts_entry.entry_type == client_pb2.X509_ENTRY:
                der_cert = ts_entry.asn1_cert
                file = open("cert.der","wb")
                file.write(der_cert)
                file.close
                #print(der_cert)
                
            else:
                print("Ups")
                der_cert = d_entry.extra_data.precert_chain_entry.pre_certificate

            #print(der_chain)
        """entries = entries.json()
        for entry in entries['entries']:
            raw = base64.b64decode(entry['leaf_input'])
            #First 15 bytes are not part of cert
            raw=raw[:0]+raw[15:]
            cert = x509.load_der_x509_certificate(raw, default_backend())
            #print(cert.subject.rfc4514_string())
            matches = check_for_match(cert.subject.rfc4514_string())
            if matches == None:
                print("No matches")
            else:
                print("Cert with serial number %s matched with domain %s" % (cert.fingerprint(cert.signature_hash_algorithm),matches))
        """
        write_currentSTH(new_sth)



def main():
    print("Maximum is 256 entries per request in Google Log.")
    google_log = "https://ct.googleapis.com/pilot/"
    if os.path.isfile("current_sth.json"):
        print("Current STH found.")
        #get_all_entries(google_log)
        check_for_new_sth(google_log)

    else:
        print("No current STH found. Starting init...")
        init_Log_Monitor(google_log)

main()
