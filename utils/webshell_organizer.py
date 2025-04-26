#!/usr/bin/env python3
import os
import sys
import json
import shutil
import datetime
from typing import Optional, Dict, List
from loguru import logger
from dataclasses import asdict
import argparse
from tqdm import tqdm

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.mylogger import setup_logger
from utils.webshell_tester import WebshellTester
from utils.webshell_analyzer import WebshellAnalyzer
from utils.logo import logo


class WebshellOrganizer:
    def __init__(self, source_dir: str, target_dir: str, test_connection: bool = True, skip_exist: bool = False, max_files: Optional[int] = None):
        self.source_dir = source_dir
        self.target_dir = target_dir
        self.analyzer = WebshellAnalyzer()
        self.tester = WebshellTester() if test_connection else None
        self.skip_exist = skip_exist
        self.max_files = max_files
        self.processed_files = []
        self.failed_files = []
        self.test_results = {
            'success': [],
            'failed': []
        }
        self.stats = {
            'start_time': datetime.datetime.now(),
            'end_time': None,
            'total_files': 0,
            'successful_files': 0,
            'failed_files': 0,
            'skipped_files': 0
        }

    def process_directory(self):
        """Process all files in the source directory"""
        logger.info(f"Starting to process directory: {self.source_dir}")
        
        # create target directory structure
        self._create_directory_structure()

        # get all file list
        all_files = []
        for root, _, files in os.walk(self.source_dir):
            for file in files:
                file_path = os.path.join(root, file)
                all_files.append(file_path)
        
        # limit the number of files to process
        if self.max_files:
            all_files = all_files[:self.max_files]

        self.stats['total_files'] = len(all_files)
        
        # use tqdm to show progress
        with tqdm(total=len(all_files), desc="Processing progress", ncols=100) as pbar:
            for file_path in all_files:
                self._process_file(file_path)
                pbar.update(1)

        # update stats
        self.stats['end_time'] = datetime.datetime.now()
        self.stats['successful_files'] = len(self.processed_files)
        self.stats['failed_files'] = len(self.failed_files)

        # output processing report
        self._generate_report()

    def _create_directory_structure(self):
        """Create target directory structure"""
        os.makedirs(os.path.join(self.target_dir, 'php'), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, 'jsp'), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, 'asp'), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, 'other'), exist_ok=True)

    def _process_file(self, file_path: str):
        """Process a single file"""
        logger.info(f"Processing file: {file_path}")

        try:
            # analyze file
            config = self.analyzer.analyze_file(file_path)
            if not config:
                self.failed_files.append(file_path)
                return

            # determine target path
            target_subdir = config.type if config.type else 'other'
            target_filename = f"{config.md5}.{config.type}"
            target_path = os.path.join(self.target_dir, target_subdir, target_filename)
            json_path = os.path.join(self.target_dir, target_subdir, f"{config.md5}.json")

            # check if file exists
            if self.skip_exist and os.path.exists(target_path) and os.path.exists(json_path):
                logger.info(f"File already exists, skipping: {file_path}")
                self.stats['skipped_files'] += 1
                return

            # test connection
            connection_success = False
            if self.tester and config.type in ['php', 'jsp']:
                logger.info(f"Testing connection: {file_path}")
                connection_success = self.tester.test_connection_sync(config)
                config.metadata.working_status = connection_success
                
                if connection_success:
                    self.test_results['success'].append(file_path)
                else:
                    self.test_results['failed'].append(file_path)
                    self.failed_files.append(file_path)
                    logger.warning(f"Connection test failed, skipping file: {file_path}")
                    return

            # only files that pass the test or don't need testing will be organized
            if not self.tester or connection_success:
                # copy file
                shutil.copy2(file_path, target_path)

                # save config file
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(asdict(config), f, indent=4, ensure_ascii=False)

                self.processed_files.append({
                    'source': file_path,
                    'target': target_path,
                    'config': json_path,
                    'working': config.metadata.working_status
                })
                logger.success(f"Successfully organized file: {file_path} -> {target_path}")

        except Exception as e:
            logger.error(f"Failed to process file: {file_path}: {str(e)}")
            self.failed_files.append(file_path)

    def _generate_report(self):
        """Generate processing report"""
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()

        logger.info("\n=== Processing report ===")
        logger.info(f"Total files: {self.stats['total_files']}")
        logger.info(f"Successful organized: {self.stats['successful_files']} files")
        logger.info(f"Failed/Unsuccessful: {self.stats['failed_files']} files")
        logger.info(f"Skipped existing: {self.stats['skipped_files']} files")
        logger.info(f"Processing time: {duration:.2f} seconds")

        if self.tester:
            logger.info("\n=== Connection test report ===")
            logger.info(f"Success: {len(self.test_results['success'])} files")
            logger.info(f"Failed: {len(self.test_results['failed'])} files")

        if self.failed_files:
            logger.info("\nFailed/Unsuccessful file list:")
            for file in self.failed_files:
                if file in self.test_results['failed']:
                    logger.info(f"- {file} (Connection test failed)")
                else:
                    logger.info(f"- {file} (Failed to process)")

        if self.processed_files:
            logger.info("\nSuccessfully organized file list:")
            for file in self.processed_files:
                logger.info(f"- {file['source']} -> {file['target']}")

        # save report to file
        report_path = os.path.join(self.target_dir, 'report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump({
                'stats': self.stats,
                'processed_files': self.processed_files,
                'failed_files': self.failed_files,
                'test_results': self.test_results
            }, f, indent=4, ensure_ascii=False, default=str)

def test_single_file(file_path: str, env: str = None, keep_container: bool = False, verbose: bool = False):
    """
    Test the analysis and connection of a single file
    Args:
        file_path: str, the path of the file to be tested
        verbose: bool, whether to show detailed information
        keep_container: bool, whether to keep the container running
    """
    if not os.path.exists(file_path):
        logger.error(f"File does not exist: {file_path}")
        return

    analyzer = WebshellAnalyzer()
    tester = WebshellTester(keep_container=keep_container)

    # analyze file
    # print analysis progress
    logger.info(f"Starting to analyze file: {file_path}")
    with tqdm(total=100, desc="Analysis progress", ncols=100) as pbar:
        config = analyzer.analyze_file(file_path)
        pbar.update(50)
        if not config:
            logger.error("File analysis failed")
            return

        # test connection
        success = tester.test_connection_sync(config)
        pbar.update(50)

    # print analysis results
    logger.info("\n=== Analysis results ===")
    logger.info(f"File type: {config.type}")
    logger.info(f"File size: {config.size} bytes")
    logger.info(f"MD5: {config.md5}")
    logger.info(f"Connection method: {config.connection.method}")
    
    if config.connection.special_auth:
        logger.info(f"Special authentication: {config.connection.special_auth['type']}")
        logger.info(f"Authentication value: {config.connection.special_auth['value']}")
    else:
        logger.info(f"Password parameter: {config.connection.password}")
        logger.info(f"Command parameter: {config.connection.param_name}")
    
    logger.info(f"Encoding: {config.connection.encoding}")

    # print connection test results
    logger.info("\n=== Connection test ===")
    if success:
        logger.success("Connection test successful")
    else:
        logger.error("Connection test failed")

    if verbose:
        # print features in detail
        logger.info("\n=== Detailed features ===")
        logger.info(f"File upload: {config.features.file_upload}")
        logger.info(f"Command execution: {config.features.command_exec}")
        logger.info(f"Database operations: {config.features.database_ops}")
        logger.info(f"Eval usage: {config.features.eval_usage}")
        logger.info(f"Obfuscated: {config.features.obfuscated}")

        # print original content
        logger.info("\n=== File content preview ===")
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            preview = content[:500] + "..." if len(content) > 500 else content
            logger.info(preview)

def main():
    setup_logger()
    logo()
    
    parser = argparse.ArgumentParser(description='WebShell Auto Organizer')
    parser.add_argument('source_dir', nargs='?', help='Source directory path')
    parser.add_argument('target_dir', nargs='?', help='Target directory path')
    parser.add_argument('--no-test', action='store_true', help='Not perform connection test')
    parser.add_argument('--skip-exist', action='store_true', help='Skip existing files')
    parser.add_argument('--test-file', help='Test a single file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed information')
    parser.add_argument('--max-files', type=int, help='Maximum number of files to process')
    
    args = parser.parse_args()

    if args.test_file:
        # test a single file
        test_single_file(args.test_file, args.verbose)
        return

    if not args.source_dir or not args.target_dir:
        parser.print_help()
        sys.exit(1)

    organizer = WebshellOrganizer(
        args.source_dir,
        args.target_dir,
        test_connection=not args.no_test,
        skip_exist=args.skip_exist,
        max_files=args.max_files
    )
    organizer.process_directory()

if __name__ == "__main__":
    main() 