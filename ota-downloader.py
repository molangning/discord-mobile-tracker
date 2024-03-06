#!/usr/bin/env python3

from bs4 import BeautifulSoup
import requests
import json
import re
from datetime import datetime
from queue import Queue
from queue import Empty
import threading
from decimal import Decimal
from hashlib import md5
from os import path
from os import listdir
from os import makedirs
from time import sleep
from shutil import copyfile
from random import uniform

# From discord.client_info.ClientInfo.init
# Does it even matter if we use this ua string??
DISCORD_UA = "Discord-Android/%s;RNA"
GOOGLE_APP_STORE_URL = "https://play.google.com/store/apps/details?id=com.discord"
APPLE_APP_STORE_URL = "https://apps.apple.com/app/discord-chat-talk-hangout/id985746746"
MANIFEST_URL = "https://discord.com/%s/%s/manifest.json"
ASSET_URL = "https://discord.com/assets/%s/%s/%s"
BEST_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2759.74 Safari/537.36"

def clean_exit():
    print("Exiting...")
    exit()

# Wrapper function
def requests_with_ua(url, ua=""):
    if len(ua) > 0:
        headers = {
        "User-Agent": ua
        }
    else:
        headers={}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return (r.status_code, "")
    return (200, r.text)

# Another wrapper, it's probably better for me to create a class but meh.
def get_manifest_file(os_type, version):
    return requests_with_ua(MANIFEST_URL%(os_type, version), DISCORD_UA%(version))

def download_file_stream(url,path,headers):

    # print(f"[+] Downloading file to {path}")    

    sleep(uniform(0.1, 0.5))

    download_done = False
    
    for _ in range(5): 
        with requests.get(url, headers=headers, stream=True) as r:
            # print("[+] Downloading %s"%(download_url))
            if r.status_code != 200:
                print("[!] Sleeping for a few seconds as we have hit a %s"%(r.status_code))
                sleep(uniform(2.0, 2.5))
                break
            
            with open(path,'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            download_done = True

    # Sleep for a while to prevent rate limits
    sleep(uniform(0.05, 0.1))

    if download_done is False:
        print(f"[!] Failed to download file {url}")

def status_check(download_queue: Queue, queue_done: threading.Event):
    while True:
        if queue_done.is_set() and download_queue.empty():
            return
        
        print(f"[+] {download_queue.qsize()} tasks left")

        sleep(2.5)

def download_handler(download_queue: Queue, queue_done: threading.Event):
    while True:
        if queue_done.is_set() and download_queue.empty():
            return
        
        try:
            task = download_queue.get_nowait()
            download_file_stream(*task)
            download_queue.task_done()

        except Empty:
            continue

def download_ota(base_path, manifest, ua, os_type, previous_version_base_path = None):
    
    headers = {
            "User-Agent": ua
            }
    
    threads = []
    download_tasks = Queue()
    is_done = threading.Event()
    manifest_keys = list(manifest.keys())

    if "metadata" not in manifest_keys:
        print("[!] Error, metadata field not in manifest")
        clean_exit()
    metadata = manifest["metadata"]
    
    if "commit" not in manifest["metadata"].keys():
        print("[!] Error, commit not in metadata")
        clean_exit()
    commit = metadata["commit"]
    
    if "hashes" not in manifest_keys:
        print("[!] Error, hashes field not in manifest")
        clean_exit()
    hashes = manifest["hashes"]

    if "patches" not in manifest_keys:
        print("[!] Warning, patches field not in manifest")
        patches = {}
    else:
        patches = manifest["patches"]

    print("[+] Got a list of %s regular files and %s patches"%(len(hashes), len(patches)))

    print("[+] Queueing files needed for downloading...")

    for i,v in hashes.items():
        output_path = i
        if output_path.endswith("/"):
            output_path = output_path[:-1]
        
        if os_type == "android":
            if not i.startswith("app/src/main/"):
                print("[!] skipping %s as it does not start with app/src/main/"%(i))
                continue
            output_path = output_path[13:]

        if "/.." in v or "\.." in v:
            print("[!] skipping %s as it may allow directory traversal attacks"%(i))
            continue

        current_output_path = path.join(base_path, output_path)
        current_output_dir="/".join(current_output_path.split('/')[:-1])
        
        if not current_output_dir:
            current_output_dir = "."

        if not path.isdir(current_output_dir):
            # print("[+] Creating directory %s"%(current_output_dir))
            makedirs(current_output_dir)

        if previous_version_base_path is not None:
            previous_version_output_path = path.join(previous_version_base_path,output_path)

        if path.isfile(current_output_path) and md5(open(current_output_path,"rb").read()).hexdigest() == v:
            continue

        if previous_version_base_path and path.isfile(previous_version_output_path) and md5(open(previous_version_output_path,"rb").read()).hexdigest() == v:
            # print(f"[+] Using previous file from last version from {previous_version_output_path}")
            copyfile(previous_version_output_path, current_output_path)
            continue

        download_url = ASSET_URL%(os_type, commit, i)
        download_tasks.put([download_url, current_output_path, headers])

    for i,v in patches.items():
        output_path = v
        if output_path.endswith("/"):
            output_path = output_path[:-1]
        
        if os_type == "android":
            if not v.startswith("app/src/main/"):
                print("[!] Skipping %s as it does not start with app/src/main/"%(v))
                continue
            output_path = output_path[13:]
        output_path = path.join(base_path,output_path)
        
        if "/.." in v or "\.." in v:
            print("[!] Skipping %s as it may allow directory traversal attacks"%(v))
            continue
        
        output_dir="/".join(output_path.split('/')[:-1])
        if not output_dir:
            output_dir="."
            
        if not path.isdir(output_dir):
            print("[!] Creating directory %s"%(output_dir))
            makedirs(output_dir)
        
        download_url = ASSET_URL%(os_type, commit, v)
        download_tasks.put([download_url, output_path, headers])

    print("[+] Done queueing all tasks")

    if download_tasks.qsize() == 0:
        print("[!] No files in download queue!")
        return
    
    print(f"[+] Got {download_tasks.qsize()} files to download")
    
    print("[+] Starting required threads...")

    for _ in range(16):
        thread = threading.Thread(target = download_handler, args = [download_tasks, is_done])
        thread.start()
        threads.append(thread)

    print("[+] Done starting threads")
    
    is_done.set()

    thread = threading.Thread(target = status_check, args = [download_tasks, is_done])
    thread.start()
    threads.append(thread)

    for thread in threads:
        thread.join()

    download_tasks.join()

    print("[+] All files downloaded")

def process_ota_versions(versions, os_type):
    for i in versions:

        ota_version = str(i)

        if ota_version.isdigit():
            ota_version+=".0"

        closest_version = None
        closest_version_path = None
        
        if not path.isdir(os_type):
            makedirs(os_type)

        old_versions = listdir(os_type)
        
        if ota_version in old_versions:
            old_versions.remove(ota_version)

        if len(old_versions) > 0:
            old_versions = sorted(old_versions, key = lambda x: abs(Decimal(ota_version) - Decimal(x)))
            closest_version = old_versions[0]

        if closest_version is not None:
            print(f"[+] Sourcing files from {closest_version}")
            closest_version_path = path.join(os_type, closest_version)

        print(f"[+] Trying to get {ota_version} for {os_type}") 

        status_code, req_content = get_manifest_file(os_type, ota_version)

        if status_code != 200:
            # Fast fail
            print("[!] Discord returned a non 200 status code for android manifest.json")
            print("="*50)
            continue

        try:
            manifest = json.loads(req_content)
        except Exception as e:
            print("[!] Error decoding manifest.json!")
            clean_exit()

        ota_root_path = path.join(os_type, ota_version)

        if not path.isdir(ota_root_path):
            makedirs(ota_root_path)

        frozen_manifest = json.dumps(manifest, indent=4)

        for manifest_file in [path.join(ota_root_path, x) for x in listdir(ota_root_path) if x.startswith("manifest")]:
            if open(manifest_file, "r").read() == frozen_manifest:
                break
        else:
            open(path.join(ota_root_path, f"manifest_{int(datetime.today().timestamp())}.json"), "w").write(frozen_manifest)

        print(f"[+] Starting {os_type} ota checks")
        download_ota(ota_root_path, manifest, DISCORD_UA, os_type, closest_version_path)
        print(f"[+] Finished {os_type} ota checks!")
        print("="*50)


print("[+] Getting discord's version on Google play store")
status_code, req_content = requests_with_ua(GOOGLE_APP_STORE_URL, BEST_UA)

if status_code != 200:
    print("[!] Google play store returned a non 200 status code!")
    print("[!] Expected 200 status code, got %i instead"%(status_code))
    clean_exit()

android_versions = list(set(re.findall(r"\"([0-9]*\.[0-9]*) - Stable\"", req_content)))
process_ota_versions(android_versions, "android")

print("[+] Getting discord's version on Apple app store")
status_code, req_content = requests_with_ua(APPLE_APP_STORE_URL, BEST_UA)

if status_code != 200:
    print("[!] Apple app store returned a non 200 status code!")
    print("[!] Expected 200 status code, got %i instead"%(status_code))
    clean_exit()

(version_history_raw,) = re.search(r"versionHistory\\\":(\[.*?\])", req_content).groups(1)
version_history = json.loads(version_history_raw.replace("\\\"",'"'))
ios_versions = list(set([x["versionDisplay"] for x in version_history]))

process_ota_versions(ios_versions, "ios")