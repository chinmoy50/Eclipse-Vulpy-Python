import argparse
import os
import zipfile
import sys

try:
    import requests
except ImportError:
    print("The 'requests' module is not installed. Please install it using 'pip install requests' and try again.")
    sys.exit(1)

import json
import logging
import shutil
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IntruceptScanTool:
    def __init__(self, project_path):
        self.project_path = project_path
        self.config = self.read_config()

    def read_config(self):
        config_path = os.path.join(self.project_path, 'intrucept-config.txt')
        config = {}
        try:
            with open(config_path, 'r') as f:
                for line in f:
                    key, value = line.strip().split('=')
                    config[key.strip()] = value.strip()
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            return None
        return config

    def create_zip(self, output_path):
        temp_dir = os.path.join(os.path.dirname(output_path), 'temp_project_folder')
        project_name = os.path.basename(self.project_path)
        temp_project_dir = os.path.join(temp_dir, project_name)
        
        # Cleanup: Remove existing temporary directory if it exists
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        
        # Create temporary directory
        os.makedirs(temp_project_dir)
        
        try:
            # Copy project files to temporary directory
            for item in os.listdir(self.project_path):
                s = os.path.join(self.project_path, item)
                d = os.path.join(temp_project_dir, item)
                if os.path.isdir(s):
                    if item not in ['node_modules', '.git', 'temp_project_folder']:
                        shutil.copytree(s, d, symlinks=False, ignore=shutil.ignore_patterns('temp_project_folder'))
                else:
                    if item != 'intrucept-config.txt':
                        shutil.copy2(s, d)
            
            # Create zip file
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zipf.write(file_path, arcname)
            
            logger.info(f"Project zipped successfully: {output_path}")
        except Exception as e:
            logger.error(f"Error during zip creation: {str(e)}")
            raise
        finally:
            # Clean up temporary directory
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    def send_scan_request(self, zip_path, scan_type):
        api_url = {
            'SAST': 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/sast-scans',
            'SCA': 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/sca-scans'
        }[scan_type]

        with open(zip_path, 'rb') as f:
            files = {'projectZipFile': ('project.zip', f)}
            data = {
                'applicationId': self.config['APPLICATION_ID'],
                'scanName': f'New {scan_type} Scan from Cross-Platform Tool',
                'language': self.detect_language()
            }
            headers = {
                'Client-ID': self.config['CLIENT_ID'],
                'Client-Secret': self.config['CLIENT_SECRET']
            }
            response = requests.post(api_url, files=files, data=data, headers=headers)
        return response.json()

    def detect_language(self):
        if any(Path(self.project_path).glob('*.py')):
            return 'python'
        elif any(Path(self.project_path).glob('*.js')):
            return 'javascript'
        elif any(Path(self.project_path).glob('*.java')):
            return 'java'
        else:
            return 'unknown'

    def perform_scan(self, scan_type):
        if not self.config:
            return

        zip_path = os.path.join(self.project_path, 'project.zip')
        self.create_zip(zip_path)

        try:
            logger.info(f"Initiating {scan_type} scan...")
            response = self.send_scan_request(zip_path, scan_type)
            
            if 'vulnsTable' in response:
                if response['vulnsTable'].strip():
                    logger.info("Vulnerabilities found:")
                    print(response['vulnsTable'])
                else:
                    logger.info("No vulnerabilities were found.")
            else:
                logger.warning(f"{scan_type} scan completed, but no vulnerability data was returned.")
                logger.info("Full response:")
                print(json.dumps(response, indent=2))
        except Exception as e:
            logger.error(f"Error during {scan_type} scan: {str(e)}")
        finally:
            if os.path.exists(zip_path):
                os.remove(zip_path)

def main():
    parser = argparse.ArgumentParser(description='Perform SAST or SCA scan on a project.')
    parser.add_argument('scan_type', choices=['SAST', 'SCA'], help='Type of scan to perform')
    parser.add_argument('project_path', help='Path to the project directory')
    args = parser.parse_args()

    tool = IntruceptScanTool(args.project_path)
    tool.perform_scan(args.scan_type)

if __name__ == "__main__":
    main()
