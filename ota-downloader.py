#!/usr/bin/env python3

from bs4 import BeautifulSoup
import requests
import json
import re
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
    
    print("[+] Starting required threads...")

    for _ in range(16):
        thread = threading.Thread(target = download_handler, args = [download_tasks, is_done])
        thread.start()
        threads.append(thread)

    print("[+] Done starting threads")

    print("[+] Queueing files needed for downloading...")

    have_files = 0
    is_downloading = False

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
            
        have_files += 1

        if not path.isdir(current_output_dir):
            print("[+] Creating directory %s"%(current_output_dir))
            makedirs(current_output_dir)

        if previous_version_base_path is not None:
            previous_version_output_path = path.join(previous_version_base_path,output_path)

        if path.isfile(current_output_path) and md5(open(current_output_path,"rb").read()).hexdigest() == v:
            continue

        if previous_version_base_path and path.isfile(previous_version_output_path) and md5(open(previous_version_output_path,"rb").read()).hexdigest() == v:
            print(f"[+] Using previous file from last version from {previous_version_output_path}")
            copyfile(previous_version_output_path, current_output_path)
            continue
        
        if is_downloading is False:
            print(f"[+] Starting download for this version after {have_files} verified files.")
    
        is_downloading = True

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
    
    is_done.set()

    thread = threading.Thread(target = status_check, args = [download_tasks, is_done])
    thread.start()
    threads.append(thread)

    for thread in threads:
        thread.join()

    download_tasks.join()

    print("[+] All files downloaded")


# Screw this hack. If it crashes it's def on me
# ik I can return the first one, but idk if it will change
# So this piece of code searches through the entire page

print("[+] Getting discord's version on Google play store")
status_code, req_content = requests_with_ua(GOOGLE_APP_STORE_URL, BEST_UA)

if status_code != 200:
    print("[!] Google play store returned a non 200 status code!")
    print("[!] Expected 200 status code, got %i instead"%(status_code))
    clean_exit()

android_versions = re.findall(r"\"[0-9]*\.[0-9]* - Stable\"", req_content)

validated_android_versions = set()

for i in android_versions:
    version = i[1:-1]
    version = version.replace(" - Stable","")
    version = version.strip() # Just in case something went wonky

    # Check if version is float with regex before we blow ourselves sky high trying to convert it into decimal
    if not re.match("^[0-9]*\.[0-9]*$", version):
        continue
    
    try:
        # We use the decimal library as floating point arithmetic gets quirky 
        version = Decimal(version)
        validated_android_versions.add(version)
    except:
        # how did you trigger this bruh
        print("[!] Error in converting version string %s to decimal"%(i))

for i in validated_android_versions:

    # Change the type
    android_version = str(i)
    closest_version = None
    previous_android_version_path = None
    
    old_versions = listdir("android")
    
    if android_version in old_versions:
        old_versions.remove(android_version)

    if len(old_versions) > 0:
        old_versions = sorted(old_versions, key = lambda x: abs(Decimal(android_version) - Decimal(x)))
        closest_version = old_versions[0]

    if closest_version is not None:
        print(f"[+] Sourcing files from {closest_version}")
        previous_android_version_path = f"android/{closest_version}"

    print("[+] Testing android version %s"%(android_version))

    status_code, req_content = get_manifest_file("android", android_version)

    if status_code != 200:
        # Fast fail
        print("[!] Discord returned a non 200 status code for android manifest.json")
        continue

    try:
        android_manifest = json.loads(req_content)
    except Exception as e:
        print("[!] Error decoding Android manifest.json!")
        clean_exit()

    print("[+] Starting android ota checks")
    download_ota(f"android/{android_version}", android_manifest, DISCORD_UA, "android", previous_android_version_path)
    print("[+] Finished android ota checks!")
    print("="*30)

print("[+] Getting discord's version on Apple app store")
status_code, req_content = requests_with_ua(APPLE_APP_STORE_URL, BEST_UA)

if status_code != 200:
    print("[!] Apple app store returned a non 200 status code!")
    print("[!] Expected 200 status code, got %i instead"%(status_code))
    clean_exit()

soup = BeautifulSoup(req_content, "html.parser")
version = soup.find("p",{"class":"whats-new__latest__version"}).string

if len(version) == 0:
    print("[!] Version string can't be found")
    print("[!] Don't worry, this is normal. It means Apple changed their dom.")
    print("[!] Submit a issue on github to let me know!")
    clean_exit()

if not version.startswith("Version "):
    print("[!] Got a invalid version string from Apple app store")
    print("[!] Got %s"%(version))
    clean_exit()

version = version[8:]

if version.isdigit():
    version+=".0"

if not re.match("^[0-9]*\.[0-9]*$", version):
    print("[!] Version number is not a decimal!")
    print("[!] Got: %s"%(version))
    clean_exit()

LATEST_IOS_VERSION = version

print("[+] Got latest iOS release: %s"%(LATEST_IOS_VERSION))

status_code, req_content = get_manifest_file("ios", LATEST_IOS_VERSION)

if status_code != 200:
    print("[!] Discord returned a non 200 status code for ios manifest.json")
    clean_exit()

try:
    ios_manifest = json.loads(req_content)
except Exception as e:
    print("[!] Error decoding ios manifest.json!")
    clean_exit()

print("[+] Starting iOS ota checks")
download_ota(f"ios/{version}", ios_manifest, LATEST_IOS_VERSION, "ios")
print("[+] Finished iOS ota checks!")