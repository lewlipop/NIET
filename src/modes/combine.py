from datetime import datetime
import os
import re
import sys
from utils.helper import gather_nessus_files, get_user_input_with_default

DEFAULT_COMPLIANCE_REPORT_ITEM = """<ReportItem port="0" svc_name="general" protocol="tcp" severity="3" pluginID="21157" pluginName="JELLYO INJECTED COMPLIANCE" pluginFamily="Policy Compliance">
<agent>JELLYO INJECTION</agent>
<compliance>false</compliance>
<compliance_check_type>JELLYO INJECTED COMPLIANCE</compliance_check_type>
<compliance_supports_parse_validation>true</compliance_supports_parse_validation>
<compliance_supports_replacement>true</compliance_supports_replacement>
<fname>JELLYO_INJECTION.nbin</fname>
<plugin_modification_date>2025/03/14</plugin_modification_date>
<plugin_name>JELLYO INJECTED COMPLIANCE</plugin_name>
<plugin_publication_date>2025/03/14</plugin_publication_date>
<plugin_type>local</plugin_type>
<risk_factor>None</risk_factor>
<script_version>$Revision: 1.843 $</script_version>
<cm:compliance-benchmark-version>2.0.0</cm:compliance-benchmark-version>
<cm:compliance-check-name>THIS IS A JELLYO INJECTED COMPLIANCE</cm:compliance-check-name>
<cm:compliance-check-id>c4cf7cac55c13209c2e8f3d674710c2342bfb9c1e78cbe38249b5e449df95cd8</cm:compliance-check-id>
<cm:compliance-actual-value>THIS COMPLIANCE WAS INJECTED AS THE NESSUS FILE DID NOT CONTAIN COMPLIANCE</cm:compliance-actual-value>
<cm:compliance-source>JELLYO INJECTED COMPLIANCE</cm:compliance-source>
<cm:compliance-audit-file>JELLYO_INJECTED_THIS_FILE_DOES_NOT_EXIST.audit</cm:compliance-audit-file>
<cm:compliance-policy-value>JELLYO INJECTED COMPLIANCE</cm:compliance-policy-value>
<cm:compliance-functional-id>bbbf74ae39</cm:compliance-functional-id>
<cm:compliance-uname>JELLYO INJECTED COMPLIANCE</cm:compliance-uname>
<cm:compliance-info>JELLYO INJECTED COMPLIANCE</cm:compliance-info>
<cm:compliance-result>PASSED</cm:compliance-result>
<cm:compliance-benchmark-profile>L2 Workstation</cm:compliance-benchmark-profile>
<cm:compliance-informational-id>d4788cd3870b4d77ede0ec59590775c8c99d6690304f9998f1f62cda7075f6a0</cm:compliance-informational-id>
<cm:compliance-reference>800-171|3.1.1,800-171|3.1.4,800-171|3.1.5,800-171|3.8.1,800-171|3.8.2,800-171|3.8.3,800-53|AC-3,800-53|AC-5,800-53|AC-6,800-53|MP-2,800-53r5|AC-3,800-53r5|AC-5,800-53r5|AC-6,800-53r5|MP-2,CN-L3|7.1.3.2(b),CN-L3|7.1.3.2(g),CN-L3|8.1.4.2(d),CN-L3|8.1.4.2(f),CN-L3|8.1.4.11(b),CN-L3|8.1.10.2(c),CN-L3|8.1.10.6(a),CN-L3|8.5.3.1,CN-L3|8.5.4.1(a),CSCv7|14.6,CSCv8|3.3,CSF|PR.AC-4,CSF|PR.DS-5,CSF|PR.PT-2,CSF|PR.PT-3,GDPR|32.1.b,HIPAA|164.306(a)(1),HIPAA|164.312(a)(1),ISO/IEC-27001|A.6.1.2,ISO/IEC-27001|A.9.4.1,ISO/IEC-27001|A.9.4.5,ITSG-33|AC-3,ITSG-33|AC-5,ITSG-33|AC-6,ITSG-33|MP-2,ITSG-33|MP-2a.,LEVEL|2A,NESA|T1.3.2,NESA|T1.3.3,NESA|T1.4.1,NESA|T4.2.1,NESA|T5.1.1,NESA|T5.2.2,NESA|T5.4.1,NESA|T5.4.4,NESA|T5.4.5,NESA|T5.5.4,NESA|T5.6.1,NESA|T7.5.2,NESA|T7.5.3,NIAv2|AM1,NIAv2|AM3,NIAv2|AM23f,NIAv2|SS13c,NIAv2|SS15c,NIAv2|SS29,PCI-DSSv3.2.1|7.1.2,PCI-DSSv4.0|7.2.1,PCI-DSSv4.0|7.2.2,QCSC-v1|3.2,QCSC-v1|5.2.2,QCSC-v1|6.2,QCSC-v1|13.2,SWIFT-CSCv1|5.1,TBA-FIISB|31.1,TBA-FIISB|31.4.2,TBA-FIISB|31.4.3</cm:compliance-reference>
<cm:compliance-solution>JELLYO INJECTED</cm:compliance-solution>
<cm:compliance-benchmark-name>JELLYO INJECTED COMPLIANCE</cm:compliance-benchmark-name>
<cm:compliance-control-id>28b30b858a3e497b830c7d2268ebb905eae46d0f545328463f0971da9b8e7958</cm:compliance-control-id>
<cm:compliance-see-also>https://JELLYO.NET</cm:compliance-see-also>
<cm:compliance-full-id>c4cf7cac55c13209c2e8f3d674710c2342bfb9c1e78cbe38249b5e449df95cd8</cm:compliance-full-id>
</ReportItem>
"""


def trim_source_content(file_path):
    """
    Reads a source file and returns only the content from the first <ReportHost 
    to the last </ReportHost> (inclusive), discarding extraneous content.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    # DOTALL mode: '.' matches newlines.
    match = re.search(r'(?s)(<ReportHost.*</ReportHost>)', content)

    """
    (?s) = DOTALL mode → . matches newlines
    <ReportHost.*</ReportHost>:
    matches from the first <ReportHost
    all the way to the last </ReportHost>

    If <ReportHost> exists → returns ALL <ReportHost>...</ReportHost> XML blocks in the .nessus file as one single combined string.
    If not → return entire file (fallback safety)
    """
    if match:
        return match.group(1)
    else:
        return content

def get_nessus_report_hosts_from_content(content):
    """
    Extracts ReportHost blocks from the provided content.
    The regex looks for a <ReportHost ...> tag and lazily captures everything until the next
    <ReportHost ...> tag or the end of the string.

    Splits the trimmed content into INDIVIDUAL ReportHost blocks
    """
    pattern = r'(<ReportHost[^>]*>.*?)(?=<ReportHost[^>]*>|$)'
    hosts = re.findall(pattern, content, flags=re.DOTALL)
    return hosts

def get_destination_hosts(file_path):
    """
    Extracts ReportHost blocks from the destination file.
    Assumes that each ReportHost block is wrapped with a closing </ReportHost> tag.

    <ReportHost> is the per-host container in a Nessus .nessus file. Each <ReportHost> 
    represents one scanned host (IP / hostname) and contains all findings, plugins, ports, and metadata for that host.

    Reads the entire .nessus file as text
    Finds every complete <ReportHost> ... </ReportHost> block
    Returns them as a list of strings
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    pattern = r'(<ReportHost[^>]*>.*?</ReportHost>)'
    hosts = re.findall(pattern, content, flags=re.DOTALL)
    return hosts

def combine_hosts(dest_hosts_tuples, source_hosts_tuples, remove_duplicates_flag, logger=None):
    """
    Combines host blocks from the destination and source files.
    Each host block is paired with its 'name' attribute (if present) and its origin filepath.
    
    If remove_duplicates_flag is set to "ask" or "auto", then for any host name that appears
    more than once the user is prompted (or auto-selected) which file's block to keep.
    Otherwise, all blocks are combined (duplicates left in).

    1.  Combines all <ReportHost> blocks from:
        the destination .nessus files and all source .nessus files
    2. Groups hosts by their name attribute (IP / hostname)
    3. Detects duplicates (same name appearing in multiple files)
    4. Resolves duplicates based on remove_duplicates_flag:
    5. "ask" → user chooses which file’s host to keep
    6. "auto" → automatically keeps the first one
    7. otherwise → keeps all duplicates
    8. Returns a list of <ReportHost>...</ReportHost> XML blocks only
    
    """
    
    # Combine both lists. Now there are all hosts from all Nessus files in one list.
    combined = dest_hosts_tuples + source_hosts_tuples
    
    # Group by host name.
    host_dict = {} # Create a dictionary callled host_dict

    # Create a host_name key, where the default value is an empty list, then append the block and origin value.
    # block is the <ReportHost></ReportHost> block, while origin is the location of the file path.
    for block, host_name, origin in combined:
        host_dict.setdefault(host_name, []).append((block, origin)) 
    

    # host_name	--> "192.168.1.10" (example)
    # entries --> list of tuples [(block, origin)]
    final_hosts = []
    for host_name, entries in host_dict.items():
        if len(entries) == 1: # IF there are only 1 entry found within the key
            final_hosts.append(entries[0][0]) #the XML <ReportHost>...</ReportHost> string is being appended aka the block variable
        else:
            if remove_duplicates_flag and remove_duplicates_flag.lower() in ["ask", "auto"]:
                if remove_duplicates_flag.lower() == "ask":
                    print(f"Duplicate host found for name '{host_name}':")
                    for idx, (block, origin) in enumerate(entries, start=1):
                        print(f"{idx}. {origin}")
                valid_choice = False
                while not valid_choice:
                    try:
                        if remove_duplicates_flag.lower() == "auto":
                            choice = 1
                        else:
                            choice = get_user_input_with_default(
                                f"Choose which file's ReportHost to keep for host '{host_name}' (1-{len(entries)}) [1]: ",
                                default=1, logger=logger)
                        choice = int(choice)
                        if 1 <= choice <= len(entries):
                            final_hosts.append(entries[choice - 1][0])
                            valid_choice = True
                        else:
                            if logger:
                                logger.error("Invalid choice, please try again.")
                            else:
                                print("Invalid choice, please try again.")
                    except ValueError:
                        if logger:
                            logger.error("Please enter a valid number.")
                        else:
                            print("Please enter a valid number.")
            else:
                # If not removing duplicates, keep all.
                for block, origin in entries:
                    final_hosts.append(block)
    return final_hosts # return the XML <ReportHost>...</ReportHost> string is being appended aka the block variable

def update_report_tag(content, new_report_name):
    """
    Updates the name attribute of the <Report> tag to new_report_name.
    If a name attribute already exists, it is replaced.
    If not, one is inserted after the <Report tag.
    """
    # Pattern to find a name attribute in the <Report> tag.
    pattern = r'(<Report\b[^>]*\bname\s*=\s*")([^"]*)(")'

    # If a name already exists, replaces only the value of name="", once.
    if re.search(pattern, content):
        content = re.sub(pattern, lambda m: f'{m.group(1)}{new_report_name}{m.group(3)}', content, count=1)
    else:
        # Insert the name attribute after <Report, i.e. inserts name="Merged Scan" right after <Report.
        content = re.sub(r'(<Report\b)', r'\1 name="{}"'.format(new_report_name), content, count=1)
    return content

def update_destination_file(destination_file, final_hosts, output_file, new_report_name=None, logger=None):
    """
    Removes all existing ReportHost blocks from the destination file, inserts the 
    final list of ReportHost blocks (resolved for duplicates and processed for compliance) 
    before the closing </Report> tag, and optionally updates the <Report> tag's name attribute.
    The updated content is then written to a new output file.

    # output_file is the name of the combined Nessus file
    # new_report_name is the name of the Merged Scan
    """

    # Read the destination Nessus file
    with open(destination_file, 'r', encoding='utf-8') as f:
        dest_content = f.read()
    
    # Remove all existing ReportHost blocks in the destination file.
    # So now the file has:
    # <Report> start
    # no hosts
    # </Report> end
    dest_content_no_hosts = re.sub(r'(?s)<ReportHost[^>]*>.*?</ReportHost>', '', dest_content)
    
    # Combine final host blocks into a single XML string
    insert_content = "\n".join(final_hosts)
    
    # Insert the combined host blocks just before the closing </Report> tag.
    updated_content = re.sub(r'(</Report>)', lambda m: f"{insert_content}\n{m.group(1)}", dest_content_no_hosts)
    
    # If a new report name for the Merged Scan is provided, update the <Report> tag.
    if new_report_name:
        updated_content = update_report_tag(updated_content, new_report_name)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(updated_content)

def inject_compliance_to_host(host, compliance_item):
    """
    Injects the provided compliance_item into the host block,
    just before the closing </ReportHost> tag.
    """
    # Insert the compliance item before the closing tag.
    return re.sub(r'(</ReportHost>)', compliance_item + r'\n\1', host, count=1, flags=re.DOTALL)

def process_compliance_for_hosts(final_hosts, compliance_flag, compliance_item, logger=None):
    """
    Iterates over each host block and checks for a <compliance> tag.
    Depending on the compliance_flag or user input, it will:
     - Remove the host if chosen.
     - Inject the compliance ReportItem if chosen.
     - Leave the host unchanged.
    Returns a new list of host blocks.
    """
    processed_hosts = []
    for host in final_hosts:
        if "<compliance>" in host:
            # Host already has a compliance tag.
            processed_hosts.append(host)
        else:
            # Extract host name for reference (if available).
            m = re.search(r'name\s*=\s*"([^"]+)"', host)
            host_name = m.group(1) if m else "Unknown"
            decision = None

            if compliance_flag is None:
                # Ask user for decision.
                prompt = (f"Host '{host_name}' has no compliance report items.\n"
                          "Choose an option:\n"
                          "1. Remove this host\n"
                          "2. Inject compliance ReportItem\n"
                          "3. Leave it as is\n"
                          "Enter choice (1-3) [2]: ")
                decision = get_user_input_with_default(prompt, default="2", logger=logger)
            else:
                # Use the uniform decision from the flag.
                flag_map = {"remove": "1", "inject": "2", "ignore": "3"}
                decision = flag_map.get(compliance_flag.lower(), "2")
            
            if decision in ["1"]:
                if logger:
                    logger.info(f"Removing host '{host_name}' due to missing compliance items.")
                # Do not add the host (i.e. remove it).
                continue
            elif decision in ["2"]:
                if logger:
                    logger.info(f"Injecting compliance ReportItem for host '{host_name}'.")
                host = inject_compliance_to_host(host, compliance_item)
                processed_hosts.append(host)
            elif decision in ["3"]:
                if logger:
                    logger.info(f"Leaving host '{host_name}' unchanged (no compliance items).")
                processed_hosts.append(host)
            else:
                if logger:
                    logger.error("Invalid choice; leaving host unchanged by default.")
                processed_hosts.append(host)
    return processed_hosts

def nessus_combine(output, scan_name, directory=None, filepaths=None, logger=None, flags=None):
    """
    Combines multiple Nessus files into one.
    
    Flags is expected to be a Namespace (or similar) containing:
      - remove_duplicates: "ask" or "auto" (or other value to leave duplicates)
      - compliance: None, "Inject", "Remove", or "Ignore"
      - compliance_path: path to a file containing the compliance ReportItem
    """
    # Use defaults via getattr if flags is provided; otherwise, use defaults.
    remove_duplicates_flag = getattr(flags, "remove_duplicates", None) if flags else None
    compliance_flag = getattr(flags, "compliance", None) if flags else None
    compliance_path = getattr(flags, "compliance_path", None) if flags else None

    if not directory and not filepaths: # If directory and filepaths are both None, then have to provide either a directory or a list of filepaths
        if logger:
            logger.error("Need to provide either a directory or a list of filepaths.")
        sys.exit(1)
    
    if not scan_name: # If the name of the merged scan is not provided
        scan_name = get_user_input_with_default(
            f"Enter the new name for the merged scan (e.g. Merged Scan) [Merged Scan {datetime.now().strftime('%Y%m%d%H%M%S')}]: ",
            validate=r'^[A-Za-z0-9_\-\s]+$',
            default=f"Merged Scan {datetime.now().strftime('%Y%m%d%H%M%S')}",
            logger=logger
        )
    
    # Use the default constant unless a compliance_path is provided.
    if compliance_path:
        try:
            with open(compliance_path, 'r', encoding='utf-8') as cf:
                compliance_item = cf.read()
        except Exception as e:
            if logger:
                logger.error(f"Failed to read compliance file '{compliance_path}': {e}")
            sys.exit(1)
    else:
        compliance_item = DEFAULT_COMPLIANCE_REPORT_ITEM
    
    # Process the destination file.
    if directory:
        if logger:
            logger.debug(f"Gathering Nessus files from {directory}")
        
        """Return a list of absolute paths for all .nessus files in the directory.
        If recursive is False, only files in the root directory are returned."""
        nessus_files = gather_nessus_files(directory)
        if filepaths:
            for filepath in filepaths:
                if os.path.isfile(filepath) and filepath.endswith('.nessus'):
                    nessus_files.append(filepath)
                else:
                    if logger:
                        logger.error(f"File '{filepath}' is not a valid .nessus file.")
    else:
        nessus_files = filepaths
    
    if len(nessus_files) == 0: #If there are no nessus files found
        if logger:
            logger.error("No Nessus files found in the directory.")
        sys.exit(1)
        
    if len(nessus_files) == 1: # If there are only 1 Nessus File found
        if logger:
            logger.error("Need more than 1 Nessus file in the directory to combine.")
        sys.exit(1)
    
    # The first .nessus file becomes the destination
    # All other files will be merged into this one
    destination_file = nessus_files[0]
    

    """
    Reads the entire .nessus file as text
    Finds every complete <ReportHost> ... </ReportHost> block
    Returns them as a list of strings containing individual <ReportHost>...</ReportHost> block 
    stored in the dest_host_list list variable
    """
    dest_hosts_list = get_destination_hosts(destination_file)

    """
    For each ReportHost block within the dest_hosts_list, use regex to find the string name="__", and then extract out the host name
    The ReportHost block (Host), the host name (host_name) and the destination_file (where the ReportHost block originate from) are grouped togetehr to form a tuple,
    and then append to the dest_hosts_tuples list.
    """

    dest_hosts_tuples = []
    for host in dest_hosts_list:
        m = re.search(r'name\s*=\s*"([^"]+)"', host) # Regex finds the value name="192.168.1.10" / name="server01"
        host_name = m.group(1) if m else None # host_name = "192.168.1.10" / host_name = "server01"
        dest_hosts_tuples.append((host, # full <ReportHost>...</ReportHost> block
                                  host_name, # extracted name attribute
                                  destination_file)) # which .nessus file it came from
    
    """
    Process the remaining files within the nessus_files list.
    For each file in the nessus_files list
    1. Extract out ALL the <ReportHost>...</ReportHost> XML blocks in the .nessus file as one single combined string
    (trim_source_content(src_file))
    2. Split the one single combined string above as a list containing multiple individual ReportHost blocks.
    3. For each ReportHost block, use regex to find the string name="__", and then extract out the host name
    4. The ReportHost block (Host), the host name (host_name) and the src_file (where the ReportHost block originate from) are grouped togetehr to form a tuple,
    and then append to the source_hosts_tuples list.

    Entire process is repeated for the next nessus file in the nessus_files list, until the nessus_files list ends.

    """
    source_hosts_tuples = []
    for src_file in nessus_files[1:]:
        trimmed_content = trim_source_content(src_file) # returns ALL <ReportHost>...</ReportHost> XML blocks in the .nessus file as one single combined string.
        src_hosts = get_nessus_report_hosts_from_content(trimmed_content) # Splits the trimmed content into a list containing INDIVIDUAL ReportHost blocks
        for host in src_hosts:
            m = re.search(r'name\s*=\s*"([^"]+)"', host)
            host_name = m.group(1) if m else None
            source_hosts_tuples.append((host, # full <ReportHost>...</ReportHost> block
                                        host_name, # extracted name attribute 
                                         src_file)) # which .nessus file it came from
    
    if logger:
        logger.debug("Combining Nessus files...")

    # Return a combined list of Individual <ReportHost></ReportHost> block from all the .nessus files in the nessus_file list 
    final_hosts = combine_hosts(dest_hosts_tuples, source_hosts_tuples, remove_duplicates_flag, logger=logger)
    
    # Process each of the <ReportHost></ReportHost> block to check if there is the presennce of compliance
    # Return a list of <ReportHost></ReportHost> block that is properly being processsed with the presence of compliance items/<compliance> tag  
    final_hosts = process_compliance_for_hosts(final_hosts, compliance_flag, compliance_item, logger=logger)
    
    # Update the destination file and write the result to the output file.
    # output is the name of the combined Nessus file
    # scan_name is the name of the Merged Scan
    update_destination_file(destination_file, final_hosts, output, new_report_name=scan_name, logger=logger)
    if logger:
        logger.info(f"Combined Nessus files into {output}")
